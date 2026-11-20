"""로그인 · 2단계 인증(TOTP) · 로그아웃 · 비밀번호 변경 · 재인증."""
import secrets
import time
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete
from sqlalchemy.orm import Session as DB

from . import config
from .db import get_db
from .kvstore import kv_get, kv_set
from .models import Session, User, now
from .security import (TRUST_COOKIE, audit, check_totp, clear_cookie, client_ip, create_session, current_session, enc,
                       hash_password, ip_rate_ok, new_totp_secret, password_problem, require_user, set_cookie,
                       totp_uri, trust_hash, verify_password)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    remember: bool = False


class CodeIn(BaseModel):
    code: str = Field(max_length=12)
    trust: bool = False


def _trusted(req: Request, db: DB, u: User) -> bool:
    """이 브라우저가 OTP를 이미 통과한 신뢰 기기인지 (모든 기기 로그아웃·비밀번호 변경 시 무효)."""
    tok = req.cookies.get(TRUST_COOKIE)
    if not tok or not u.totp_enabled:
        return False
    v = kv_get(db, trust_hash(tok)) or {}
    gen = (kv_get(db, f"trust_gen:{u.id}") or {}).get("g", 0)
    return v.get("uid") == u.id and v.get("g", 0) == gen and v.get("exp", 0) > time.time()


def _give_trust(resp: Response, db: DB, u: User) -> None:
    tok = secrets.token_urlsafe(32)
    gen = (kv_get(db, f"trust_gen:{u.id}") or {}).get("g", 0)
    kv_set(db, trust_hash(tok), {"uid": u.id, "g": gen, "exp": time.time() + config.TRUST_DAYS * 86400})
    resp.set_cookie(TRUST_COOKIE, tok, httponly=True, secure=config.COOKIE_SECURE, samesite="strict",
                    max_age=config.TRUST_DAYS * 86400, path="/")


def _revoke_trust(db: DB, uid: int) -> None:
    gen = (kv_get(db, f"trust_gen:{uid}") or {}).get("g", 0)
    kv_set(db, f"trust_gen:{uid}", {"g": gen + 1})


class PwChangeIn(BaseModel):
    old: str = Field(max_length=256)
    new: str = Field(max_length=256)


class PwIn(BaseModel):
    password: str = Field(max_length=256)


def _me(s: Session, u: User) -> dict:
    return {"username": u.username, "mfaOk": s.mfa_ok, "totpEnabled": u.totp_enabled, "csrf": s.csrf}


@router.post("/login")
def login(body: LoginIn, req: Request, resp: Response, db: DB = Depends(get_db)):
    ip = client_ip(req)
    if not ip_rate_ok(ip):
        raise HTTPException(429, "too_many_attempts")
    u = db.query(User).filter(User.username == body.username.strip()).first()
    if u and u.locked_until and u.locked_until > now():
        raise HTTPException(423, "locked")
    if not u or not verify_password(u.pw_hash, body.password):
        if u:
            u.failed_count += 1
            if u.failed_count >= config.LOGIN_MAX_FAIL:
                u.locked_until = now() + timedelta(minutes=config.LOGIN_LOCK_MINUTES)
                u.failed_count = 0
            db.commit()
        audit(db, u.id if u else None, "login_fail", body.username[:64], ip)
        raise HTTPException(401, "bad_credentials")
    u.failed_count = 0
    u.locked_until = None
    db.commit()
    # 비밀번호만 통과한 상태. TOTP를 아직 등록하지 않았으면 등록 화면으로, 등록했으면 코드 입력으로.
    # 신뢰 기기(OTP 1회 통과)면 바로 로그인 완료
    trusted = _trusted(req, db, u)
    tok, s = create_session(db, u, req, mfa_ok=trusted, remember=body.remember)
    set_cookie(resp, tok, body.remember)
    audit(db, u.id, "login_ok_trusted" if trusted else "login_password_ok", "remember" if body.remember else "", ip)
    return _me(s, u)


@router.get("/me")
def me(s: Session = Depends(current_session), db: DB = Depends(get_db)):
    return _me(s, db.get(User, s.user_id))


@router.post("/totp/setup")
def totp_setup(s: Session = Depends(current_session), db: DB = Depends(get_db)):
    u = db.get(User, s.user_id)
    if u.totp_enabled:
        raise HTTPException(400, "already_enabled")
    secret = new_totp_secret()
    u.totp_secret_enc = enc(secret)
    db.commit()
    return {"secret": secret, "uri": totp_uri(secret, u.username)}


@router.post("/totp/enable")
def totp_enable(body: CodeIn, req: Request, resp: Response, s: Session = Depends(current_session), db: DB = Depends(get_db)):
    u = db.get(User, s.user_id)
    if u.totp_enabled:
        raise HTTPException(400, "already_enabled")
    if not check_totp(u, body.code):
        raise HTTPException(400, "bad_code")
    u.totp_enabled = True
    s.mfa_ok = True
    db.commit()
    if body.trust:
        _give_trust(resp, db, u)
    audit(db, u.id, "totp_enabled", "", client_ip(req))
    return _me(s, u)


@router.post("/totp/verify")
def totp_verify(body: CodeIn, req: Request, resp: Response, s: Session = Depends(current_session), db: DB = Depends(get_db)):
    u = db.get(User, s.user_id)
    if not u.totp_enabled:
        raise HTTPException(400, "totp_not_enabled")
    if not ip_rate_ok(client_ip(req) + ":totp", limit=10, window=600):
        raise HTTPException(429, "too_many_attempts")
    if not check_totp(u, body.code):
        db.commit()
        audit(db, u.id, "totp_fail", "", client_ip(req))
        raise HTTPException(400, "bad_code")
    s.mfa_ok = True
    db.commit()
    if body.trust:
        _give_trust(resp, db, u)
    audit(db, u.id, "login_ok", "trust" if body.trust else "", client_ip(req))
    return _me(s, u)


@router.post("/logout")
def logout(resp: Response, s: Session = Depends(current_session), db: DB = Depends(get_db)):
    db.delete(s)
    db.commit()
    clear_cookie(resp)
    return {"ok": True}


@router.post("/logout-all")
def logout_all(resp: Response, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    uid = s.user_id
    db.execute(delete(Session).where(Session.user_id == uid))
    db.commit()
    _revoke_trust(db, uid)  # 신뢰 기기도 모두 해제 → 다음 로그인 때 OTP 다시
    clear_cookie(resp)
    resp.delete_cookie(TRUST_COOKIE, path="/")
    return {"ok": True}


@router.post("/password")
def change_password(body: PwChangeIn, req: Request, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    u = db.get(User, s.user_id)
    if not verify_password(u.pw_hash, body.old):
        raise HTTPException(400, "bad_password")
    p = password_problem(body.new)
    if p:
        raise HTTPException(400, p)
    u.pw_hash = hash_password(body.new)
    # 다른 기기의 세션은 모두 끊음
    db.execute(delete(Session).where(Session.user_id == u.id, Session.id != s.id))
    db.commit()
    _revoke_trust(db, u.id)
    audit(db, u.id, "password_changed", "", client_ip(req))
    return {"ok": True}


@router.post("/reauth")
def reauth(body: PwIn, req: Request, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    u = db.get(User, s.user_id)
    if not ip_rate_ok(client_ip(req) + ":reauth", limit=10, window=600):
        raise HTTPException(429, "too_many_attempts")
    if not verify_password(u.pw_hash, body.password):
        audit(db, u.id, "reauth_fail", "", client_ip(req))
        raise HTTPException(400, "bad_password")
    s.reauth_at = now()
    db.commit()
    return {"ok": True, "minutes": config.REAUTH_MINUTES}


@router.post("/lock")
def lock(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """비밀번호 재확인 상태를 바로 끝냄 (인감도장관리 '잠그기')."""
    s.reauth_at = None
    db.commit()
    return {"ok": True}


@router.get("/reauth-status")
def reauth_status(s: Session = Depends(require_user)):
    from .security import recent_reauth
    return {"ok": recent_reauth(s), "minutes": config.REAUTH_MINUTES}


@router.get("/sessions")
def sessions(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    rows = db.query(Session).filter(Session.user_id == s.user_id).order_by(Session.last_seen.desc()).all()
    return [{"current": r.id == s.id, "ip": r.ip, "ua": r.ua, "lastSeen": r.last_seen.isoformat(),
             "createdAt": r.created_at.isoformat()} for r in rows]
