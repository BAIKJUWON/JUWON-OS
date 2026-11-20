"""인증·암호화 도우미: 비밀번호 해시, TOTP, 세션 쿠키, CSRF, 필드 암호화, 감사 로그."""
import base64
import hashlib
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session as DB

from . import config
from .db import get_db
from .models import AuditLog, Session, User, now

COOKIE = "jos_session"
_ph = PasswordHasher()  # argon2id 기본값
_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(config.FIELD_KEY.encode()).digest()))


# ---------- 비밀번호 ----------
def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(h: str, pw: str) -> bool:
    try:
        return _ph.verify(h, pw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def password_problem(pw: str) -> str | None:
    if len(pw) < 10:
        return "비밀번호는 10자 이상이어야 합니다."
    if pw.isdigit() or pw.isalpha():
        return "비밀번호에 숫자와 문자를 섞어 주세요."
    return None


# ---------- 필드 암호화 ----------
def enc(s: str) -> str:
    return _fernet.encrypt(s.encode()).decode()


def dec(s: str) -> str:
    try:
        return _fernet.decrypt(s.encode()).decode()
    except (InvalidToken, ValueError):
        return ""


# ---------- TOTP ----------
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=config.TOTP_ISSUER)


def check_totp(user: User, code: str) -> bool:
    """앞뒤 30초 허용, 이미 쓴 코드는 다시 받지 않음."""
    if not user.totp_secret_enc:
        return False
    secret = dec(user.totp_secret_enc)
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != 6 or not secret:
        return False
    t = pyotp.TOTP(secret)
    step_now = int(time.time()) // 30
    for off in (-1, 0, 1):
        step = step_now + off
        if step <= (user.last_totp_step or 0):
            continue
        if secrets.compare_digest(t.at(step * 30), code):
            user.last_totp_step = step
            return True
    return False


# ---------- 세션 ----------
def _hash_token(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def client_ip(req: Request) -> str:
    return (req.client.host if req.client else "")[:64]


def session_hours(remember: bool) -> int:
    return config.REMEMBER_DAYS * 24 if remember else config.SESSION_HOURS


def is_remembered(s: Session) -> bool:
    """로그인 유지 세션은 만료가 기본 시간보다 길게 잡혀 있음 (DB 컬럼 추가 없이 판별)."""
    return bool(s.created_at and s.expires_at - s.created_at > timedelta(hours=config.SESSION_HOURS + 1))


def create_session(db: DB, user: User, req: Request, mfa_ok: bool, remember: bool = False) -> tuple[str, Session]:
    tok = secrets.token_urlsafe(32)
    t = now()
    s = Session(id=_hash_token(tok), user_id=user.id, csrf=secrets.token_urlsafe(24), mfa_ok=mfa_ok, created_at=t,
                expires_at=t + timedelta(hours=session_hours(remember)), ip=client_ip(req),
                ua=(req.headers.get("user-agent") or "")[:255])
    db.add(s)
    db.commit()
    return tok, s


def set_cookie(resp, tok: str, remember: bool = False) -> None:
    resp.set_cookie(COOKIE, tok, httponly=True, secure=config.COOKIE_SECURE, samesite="strict",
                    max_age=session_hours(remember) * 3600, path="/")


# ---------- 신뢰 기기 (OTP 1회) ----------
TRUST_COOKIE = "jos_trust"


def trust_hash(tok: str) -> str:
    return "trust:" + _hash_token(tok)[:56]  # kv.key 는 최대 64자


def clear_cookie(resp) -> None:
    resp.delete_cookie(COOKIE, path="/")


def current_session(req: Request, db: DB = Depends(get_db)) -> Session:
    tok = req.cookies.get(COOKIE)
    if not tok:
        raise HTTPException(401, "login_required")
    s = db.get(Session, _hash_token(tok))
    t = now()
    idle = s and not is_remembered(s) and s.last_seen < t - timedelta(minutes=config.IDLE_MINUTES)
    if not s or s.expires_at < t or idle:
        if s:
            db.delete(s)
            db.commit()
        raise HTTPException(401, "login_required")
    # 쓰기 요청은 CSRF 토큰 확인 (SameSite=Strict와 이중 방어)
    if req.method not in ("GET", "HEAD", "OPTIONS"):
        if not secrets.compare_digest(req.headers.get("x-csrf-token", ""), s.csrf):
            raise HTTPException(403, "csrf_failed")
    if (t - s.last_seen).total_seconds() > 60:
        s.last_seen = t
        db.commit()
    return s


def require_user(s: Session = Depends(current_session)) -> Session:
    if not s.mfa_ok:
        raise HTTPException(401, "mfa_required")
    return s


def recent_reauth(s: Session) -> bool:
    return bool(s.reauth_at and s.reauth_at > now() - timedelta(minutes=config.REAUTH_MINUTES))


# ---------- 로그인 시도 제한 (IP 기준, 메모리) ----------
_ip_hits: dict[str, deque] = defaultdict(deque)


def ip_rate_ok(ip: str, limit: int = 20, window: int = 600) -> bool:
    q = _ip_hits[ip]
    t = time.time()
    while q and q[0] < t - window:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(t)
    return True


def audit(db: DB, user_id: int | None, action: str, target: str = "", ip: str = "") -> None:
    db.add(AuditLog(user_id=user_id, action=action, target=target[:255], ip=ip))
    db.commit()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
