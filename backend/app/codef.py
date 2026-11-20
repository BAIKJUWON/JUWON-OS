"""CODEF — 공동인증서 기반 은행 계좌·잔액, 카드 승인내역 조회.

보안 원칙
- 인증서 파일(signCert.der / signPri.key / .pfx)과 인증서 비밀번호는 요청을 처리하는 동안 메모리에만 있고,
  CODEF로 넘긴 뒤 버립니다. 디스크·DB·로그 어디에도 저장하지 않습니다.
- 서버에는 CODEF가 돌려준 연결번호(connectedId)만 암호화해 kv 테이블에 저장합니다.

엔드포인트·필드 이름은 CODEF 공식 라이브러리(easycodef) 기준입니다. 기관코드는 금융결제원 코드 기준이며,
CODEF가 실제로 지원하는지는 개발가이드(developer.codef.io)에서 확인하세요.
"""
import base64
import json
import re
import time
import urllib.parse
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import APIRouter, Body, Depends, Form, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session as DB

from . import config
from .db import get_db
from .kvstore import HttpError, http, kv_get, kv_set
from .models import Record, Session, now
from .records import dedup_key
from .security import audit, client_ip, recent_reauth, require_user

router = APIRouter(prefix="/api/codef", tags=["codef"])

OAUTH_URL = "https://oauth.codef.io/oauth/token"
DOMAINS = {"sandbox": "https://sandbox.codef.io", "demo": "https://development.codef.io", "product": "https://api.codef.io"}

BANKS = {"0002": "KDB산업은행", "0003": "IBK기업은행", "0004": "KB국민은행", "0007": "수협은행", "0011": "NH농협은행",
         "0012": "지역농축협", "0020": "우리은행", "0023": "SC제일은행", "0027": "한국씨티은행", "0031": "iM뱅크",
         "0032": "부산은행", "0034": "광주은행", "0035": "제주은행", "0037": "전북은행", "0039": "경남은행",
         "0045": "새마을금고", "0048": "신협", "0071": "우체국", "0081": "하나은행", "0088": "신한은행", "0089": "케이뱅크"}
# 신용카드는 신한카드·KB국민카드만 씀 (필요하면 여기에 추가: 0302 현대, 0303 삼성, 0304 NH농협, 0305 BC, 0309 우리, 0311 롯데, 0313 하나)
CARDS = {"0306": "신한카드", "0301": "KB국민카드"}
MAX_CERT = 64 * 1024


def _mode() -> str:
    return config.CODEF_MODE if config.CODEF_MODE in DOMAINS else "sandbox"


def configured() -> bool:
    return bool(config.CODEF_CLIENT_ID and config.CODEF_CLIENT_SECRET and config.CODEF_PUBLIC_KEY)


def _fail(msg: str, status: int = 502):
    raise HTTPException(status, msg)


def _state(db: DB) -> dict:
    return kv_get(db, f"codef:{_mode()}") or {"connectedId": "", "orgs": []}


def _token(db: DB) -> str:
    key = f"codef_token:{_mode()}"
    saved = kv_get(db, key) or {}
    if saved.get("token") and saved.get("exp", 0) > time.time() + 600:
        return saved["token"]
    basic = base64.b64encode(f"{config.CODEF_CLIENT_ID}:{config.CODEF_CLIENT_SECRET}".encode()).decode()
    try:
        _, _, text = http("POST", OAUTH_URL, {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
                          b"grant_type=client_credentials&scope=read")
    except HttpError as e:
        if e.status == 0:
            _fail(f"CODEF 서버에 연결하지 못했습니다 (NAS 인터넷·DNS 확인): {e.body[:120]}")
        _fail(f"CODEF 토큰 발급 실패 ({e.status}). CODEF_CLIENT_ID·SECRET이 맞는지 확인하세요. {e.body[:160]}")
    try:
        data = json.loads(text)
    except ValueError:
        _fail("CODEF 토큰 응답을 읽지 못했습니다.")
    tok = data.get("access_token")
    if not tok:
        _fail("CODEF 토큰 응답에 토큰이 없습니다.")
    kv_set(db, key, {"token": tok, "exp": time.time() + int(data.get("expires_in", 3600))})
    return tok


def _call(db: DB, path: str, params: dict) -> dict:
    """CODEF 요청은 JSON을 URL 인코딩해서 보내고, 응답도 URL 인코딩된 JSON으로 옵니다."""
    body = urllib.parse.quote(json.dumps(params, ensure_ascii=False)).encode()
    try:
        _, _, text = http("POST", DOMAINS[_mode()] + path, {"Accept": "application/json", "Content-Type": "application/json",
                                                             "Authorization": f"Bearer {_token(db)}"}, body, timeout=60)
    except HttpError as e:
        if e.status == 401:
            kv_set(db, f"codef_token:{_mode()}", {})  # 키를 바꾼 경우 옛 토큰 지움
        _fail(f"CODEF 요청 실패 ({e.status or '연결 안 됨'}). {urllib.parse.unquote_plus(e.body or '')[:200]}")
    try:
        res = json.loads(urllib.parse.unquote_plus(text))
    except ValueError:
        try:
            res = json.loads(text)
        except ValueError:
            _fail(f"CODEF 응답을 읽지 못했습니다: {text[:120]}")
    return res


def _check(res: dict, what: str) -> dict:
    r = res.get("result") or {}
    code = r.get("code", "")
    if code != "CF-00000":
        extra = r.get("extraMessage") or ""
        _fail(f"{what} 실패 [{code}] {r.get('message', '')} {extra}".strip())
    return res.get("data") or {}


def _as_list(v) -> list:
    """응답 항목이 목록·단일 객체·빈 문자열 등 어떤 모양으로 와도 dict 목록으로 통일."""
    if isinstance(v, dict):
        return [v]
    if isinstance(v, list):
        return [x for x in v if isinstance(x, dict)]
    return []


def _clean_key(k: str) -> str:
    """.env에 붙여 넣은 퍼블릭 키에서 따옴표·PEM 머리글·줄바꿈·공백을 걷어 냄."""
    k = (k or "").strip().strip('"').strip("'")
    k = re.sub(r"-----(BEGIN|END)[A-Z ]*-----", "", k)
    k = k.replace("\\n", "")
    k = re.sub(r"\s+", "", k)
    return k + "=" * (-len(k) % 4)


def rsa_encrypt(text: str, public_key_b64: str) -> str:
    try:
        key = serialization.load_der_public_key(base64.b64decode(_clean_key(public_key_b64)))
    except Exception:
        _fail("CODEF_PUBLIC_KEY를 읽지 못했습니다. CODEF '키 관리'의 퍼블릭 키 전체를 한 줄로, 따옴표 없이 넣었는지 확인하세요.", 400)
    return base64.b64encode(key.encrypt(text.encode(), padding.PKCS1v15())).decode()


def _org_name(btype: str, org: str) -> str:
    return (BANKS if btype == "BK" else CARDS).get(org, org)


@router.get("/status")
def status(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    st = _state(db)
    return {"configured": configured(), "mode": _mode(), "connected": bool(st.get("connectedId")),
            "orgs": st.get("orgs", []), "lastSync": (kv_get(db, f"codef_last:{_mode()}") or {}).get("at")}


@router.get("/orgs")
def orgs(s: Session = Depends(require_user)):
    return {"BK": BANKS, "CD": CARDS}


@router.post("/connect")
async def connect(req: Request, businessType: str = Form(...), organization: str = Form(...), certFormat: str = Form("derkey"),
                  password: str = Form(...), certDer: UploadFile | None = None, certKey: UploadFile | None = None,
                  certPfx: UploadFile | None = None, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    if not configured():
        _fail("CODEF 키가 설정되지 않았습니다. .env의 CODEF_CLIENT_ID·CODEF_CLIENT_SECRET·CODEF_PUBLIC_KEY를 채우세요.", 400)
    if not recent_reauth(s):
        _fail("reauth_required", 403)
    if businessType not in ("BK", "CD") or organization not in (BANKS if businessType == "BK" else CARDS):
        _fail("기관을 다시 선택해 주세요.", 400)

    async def read(f: UploadFile | None, name: str) -> str:
        if not f:
            _fail(f"{name} 파일을 선택해 주세요.", 400)
        raw = await f.read(MAX_CERT + 1)
        if not raw or len(raw) > MAX_CERT:
            _fail(f"{name} 파일이 비었거나 너무 큽니다.", 400)
        return base64.b64encode(raw).decode()

    acct = {"countryCode": "KR", "businessType": businessType, "clientType": "P", "organization": organization,
            "loginType": "0", "password": rsa_encrypt(password, config.CODEF_PUBLIC_KEY)}
    if certFormat == "pfx":
        acct.update(certType="pfx", certFile=await read(certPfx, "인증서(.pfx)"))
    else:
        acct.update(certType="1", derFile=await read(certDer, "signCert.der"), keyFile=await read(certKey, "signPri.key"))
    password = ""  # 더 이상 쓰지 않음

    st = _state(db)
    if st.get("connectedId"):
        data = _check(_call(db, "/v1/account/add", {"connectedId": st["connectedId"], "accountList": [acct]}), "기관 추가")
    else:
        data = _check(_call(db, "/v1/account/create", {"accountList": [acct]}), "인증서 등록")
        st["connectedId"] = data.get("connectedId", "")
        if not st["connectedId"]:
            _fail("CODEF가 연결번호를 돌려주지 않았습니다.")
    errs = _as_list((data or {}).get("errorList"))
    if errs:
        e = errs[0]
        _fail(f"기관 등록 실패 [{e.get('code', '')}] {e.get('message', '')} {e.get('extraMessage', '')}".strip())
    st["orgs"] = [o for o in st.get("orgs", []) if not (o["type"] == businessType and o["org"] == organization)]
    st["orgs"].append({"type": businessType, "org": organization, "name": _org_name(businessType, organization),
                       "addedAt": datetime.now().strftime("%Y-%m-%d")})
    kv_set(db, f"codef:{_mode()}", st)
    audit(db, s.user_id, "codef_connect", f"{businessType}:{organization}", client_ip(req))
    return {"ok": True, "orgs": st["orgs"]}


@router.delete("/org/{btype}/{org}")
def disconnect(btype: str, org: str, req: Request, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    st = _state(db)
    if not st.get("connectedId"):
        _fail("연결된 인증서가 없습니다.", 400)
    acct = {"countryCode": "KR", "businessType": btype, "clientType": "P", "organization": org, "loginType": "0"}
    try:
        _check(_call(db, "/v1/account/delete", {"connectedId": st["connectedId"], "accountList": [acct]}), "연결 해제")
    except HTTPException:
        pass  # CODEF 쪽에서 이미 없는 경우에도 목록에서는 지움
    st["orgs"] = [o for o in st.get("orgs", []) if not (o["type"] == btype and o["org"] == org)]
    if not st["orgs"]:
        st["connectedId"] = ""
    kv_set(db, f"codef:{_mode()}", st)
    audit(db, s.user_id, "codef_disconnect", f"{btype}:{org}", client_ip(req))
    return {"ok": True, "orgs": st["orgs"]}


def _int(v) -> int:
    try:
        return int(float(str(v).replace(",", "") or 0))
    except ValueError:
        return 0


def _ymd(v: str) -> str:
    v = re.sub(r"\D", "", str(v or ""))
    return f"{v[:4]}-{v[4:6]}-{v[6:8]}" if len(v) >= 8 else ""


@router.post("/sync")
def sync(req: Request, payload: dict = Body(default={}), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """연결된 은행은 계좌·잔액을 '은행·증권 계좌'에, 카드는 최근 승인내역을 '수입·지출'에 반영합니다."""
    if not _state(db).get("connectedId"):
        _fail("먼저 인증서로 기관을 연결하세요.", 400)
    result = do_sync(db, int(payload.get("days") or 31))
    audit(db, s.user_id, "codef_sync", json.dumps({k: result[k] for k in ("accounts", "flows")}), client_ip(req))
    return result


def do_sync(db: DB, days: int) -> dict:
    st = _state(db)
    if not st.get("connectedId") or not configured():
        return {"accounts": 0, "flows": 0, "skipped": 0, "errors": []}
    days = max(1, min(days, 92))
    end = datetime.now()
    start = end - timedelta(days=days)
    tag = " (샌드박스 예시)" if _mode() == "sandbox" else ""
    result = {"accounts": 0, "flows": 0, "skipped": 0, "errors": []}
    done: dict = {}  # 이번 실행에서 이미 만든 계좌 — 같은 계좌가 응답에 두 번 와도 중복 생성하지 않음
    existing = {r.data.get("dedup") for r in db.query(Record).filter(Record.kind == "fin_flow").all() if r.data}
    for o in st.get("orgs", []):
        try:
            if o["type"] == "BK":
                data = _check(_call(db, "/v1/kr/bank/p/account/account-list",
                                    {"connectedId": st["connectedId"], "organization": o["org"]}), o["name"])
                found_before = result["accounts"]
                for group, label in (("resDepositTrust", "입출금"), ("resForeignCurrency", "기타"), ("resFund", "증권"), ("resLoan", "기타")):
                    for a in _as_list(data.get(group)):
                        num = re.sub(r"\D", "", str(a.get("resAccount") or ""))
                        if not num:
                            continue
                        rid = f"codef_{o['org']}_{num[-6:]}"
                        bal = _int(a.get("resAccountBalance"))
                        if group == "resLoan":
                            bal = -abs(bal)
                        payload_rec = {"inst": o["name"], "alias": (a.get("resAccountNickName") or a.get("resAccountName") or "") + tag,
                                       "type": label, "last4": num[-4:], "balance": bal, "checked": end.strftime("%Y-%m-%d"),
                                       "memo": "CODEF 인증서 조회로 자동 반영" + (" · 대출(음수)" if group == "resLoan" else ""), "auto": "codef"}
                        rec = done.get(rid) or db.get(Record, rid)
                        if rec:
                            rec.data = payload_rec
                            rec.updated_at = now()
                        else:
                            rec = Record(id=rid, kind="fin_account", entity="personal", data=payload_rec)
                            db.add(rec)
                            db.flush()
                        done[rid] = rec
                        result["accounts"] += 1
                if result["accounts"] == found_before:
                    keys = ", ".join(list(data.keys())[:10]) if isinstance(data, dict) else type(data).__name__
                    result["errors"].append(f"{o['name']}: 응답에서 계좌를 찾지 못했습니다 (응답 항목: {keys or '없음'}). 이 내용을 그대로 개발자에게 전달하세요.")
            else:
                data = _check(_call(db, "/v1/kr/card/p/account/approval-list",
                                    {"connectedId": st["connectedId"], "organization": o["org"], "birthDate": "",
                                     "startDate": start.strftime("%Y%m%d"), "endDate": end.strftime("%Y%m%d"),
                                     "orderBy": "0", "inquiryType": "1", "memberStoreInfoType": "0"}), o["name"])
                for a in _as_list(data):
                    if str(a.get("resCancelYN", "0")) not in ("0", ""):
                        continue  # 취소된 승인은 건너뜀
                    rec_data = {"date": _ymd(a.get("resUsedDate")), "dir": "지출", "method": "신용카드", "cat": "기타",
                                "amount": _int(a.get("resUsedAmount")), "memo": (a.get("resMemberStoreName") or "") + tag,
                                "source": o["name"] + (" " + str(a.get("resCardNo"))[-4:] if a.get("resCardNo") else "")}
                    key = dedup_key("fin_flow", {**rec_data, "approval": a.get("resApprovalNo", "")}, ["date", "amount", "memo", "source", "approval"])
                    if not rec_data["date"] or key in existing:
                        result["skipped"] += 1
                        continue
                    existing.add(key)
                    db.add(Record(kind="fin_flow", entity="personal", data={**rec_data, "dedup": key}))
                    result["flows"] += 1
            db.commit()
        except HTTPException as e:
            db.rollback()
            result["errors"].append(f"{o['name']}: {e.detail}")
        except Exception as e:  # 예상 못 한 응답 모양 — 다른 기관은 계속 진행
            db.rollback()
            result["errors"].append(f"{o['name']}: {type(e).__name__} {str(e)[:120]}")
    kv_set(db, f"codef_last:{_mode()}", {"at": end.isoformat()})
    return result


# ---------- 사업용 통장 거래내역 (버튼을 눌렀을 때만 조회 · 자동 수집 없음) ----------
@router.get("/bank-tx/last")
def bank_tx_last(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    st = _state(db)
    return {"configured": configured(), "mode": _mode(), "connected": [o for o in st.get("orgs", []) if o["type"] == "BK"],
            "last": kv_get(db, f"codef_banktx:{_mode()}") or {}}


@router.post("/bank-tx")
def bank_tx(req: Request, payload: dict = Body(default={}), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """{"organization": "0081"(하나은행), "account": "끝 4자리(선택)", "days": 31, "accountPassword": "(은행이 요구할 때만)"}
    조회 결과를 저장하지 않고 돌려줍니다. 화면에서 확인한 뒤 /api/records/bulk 로 저장하며 같은 거래는 건너뜁니다.
    계좌 비밀번호는 이 요청 동안 CODEF 공개키로 암호화해 넘기기만 하고 어디에도 저장하지 않습니다."""
    if not configured():
        _fail("CODEF 키가 설정되지 않았습니다. .env의 CODEF_CLIENT_ID·SECRET·PUBLIC_KEY가 필요합니다 (CODEF 이용 계약 필요).", 400)
    st = _state(db)
    org = str(payload.get("organization") or "0081")
    if org not in BANKS:
        _fail("은행 코드가 올바르지 않습니다.", 400)
    if not st.get("connectedId") or not any(o["type"] == "BK" and o["org"] == org for o in st.get("orgs", [])):
        _fail(f"{BANKS[org]}이(가) 연결돼 있지 않습니다. 금융·자산 → 인증서 연결에서 {BANKS[org]}을 먼저 연결하세요.", 400)
    days = max(1, min(int(payload.get("days") or 31), 92))
    end = datetime.now()
    start = end - timedelta(days=days)
    lst = _check(_call(db, "/v1/kr/bank/p/account/account-list", {"connectedId": st["connectedId"], "organization": org}), BANKS[org])
    accounts = [re.sub(r"\D", "", str(a.get("resAccount") or "")) for a in _as_list(lst.get("resDepositTrust"))]
    want = re.sub(r"\D", "", str(payload.get("account") or ""))
    targets = [a for a in accounts if a and (not want or a.endswith(want))]
    if not targets:
        _fail("조건에 맞는 입출금 계좌가 없습니다. 계좌 끝자리를 확인하세요." + (f" (조회된 계좌 끝자리: {', '.join(a[-4:] for a in accounts if a)})" if accounts else ""), 404)
    pw = str(payload.get("accountPassword") or "")
    rows, balances = [], {}
    for acc in targets[:5]:
        params = {"connectedId": st["connectedId"], "organization": org, "account": acc, "startDate": start.strftime("%Y%m%d"),
                  "endDate": end.strftime("%Y%m%d"), "orderBy": "0", "inquiryType": "1", "birthDate": ""}
        if pw:
            params["accountPassword"] = rsa_encrypt(pw, config.CODEF_PUBLIC_KEY)
        data = _check(_call(db, "/v1/kr/bank/p/account/transaction-list", params), f"{BANKS[org]} 거래내역")
        balances[acc[-4:]] = _int(data.get("resAccountBalance"))
        for t in _as_list(data.get("resTrHistoryList")):
            inn, out = _int(t.get("resAccountIn")), _int(t.get("resAccountOut"))
            if not (inn or out):
                continue
            memo = " ".join(str(t.get(k) or "").strip() for k in ("resAccountDesc1", "resAccountDesc2", "resAccountDesc3", "resAccountDesc4")).strip()
            rows.append({"date": _ymd(t.get("resAccountTrDate")), "time": str(t.get("resAccountTrTime") or "")[:6], "dir": "입금" if inn else "출금",
                         "amount": inn or out, "balance": _int(t.get("resAfterTranBalance")), "memo": re.sub(r"\s+", " ", memo)[:120], "last4": acc[-4:]})
    pw = ""
    info = {"at": end.strftime("%Y-%m-%d %H:%M"), "bank": BANKS[org], "accounts": list(balances.keys()), "rows": len(rows), "balances": balances, "days": days}
    kv_set(db, f"codef_banktx:{_mode()}", info)
    audit(db, s.user_id, "codef_banktx", json.dumps({"bank": org, "rows": len(rows), "days": days}), client_ip(req))
    return {**info, "rows": rows, "count": len(rows), "sandbox": _mode() == "sandbox"}
