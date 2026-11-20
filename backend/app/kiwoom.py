"""키움증권 REST API — 국내주식 계좌평가잔고(kt00018) 조회. 조회 전용.

키움 REST API는 앱키를 발급할 때 계좌가 정해지므로 계좌번호를 따로 보내지 않습니다.
도메인·필드는 키움 REST API 문서(openapi.kiwoom.com) 기준이며, 처음 연결 때 실제 응답으로 확인이 필요합니다.
"""
import json
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session as DB

from . import config
from .db import get_db
from .kvstore import HttpError, http, kv_get, kv_set
from .models import Record, Session, now
from .security import audit, client_ip, require_user

router = APIRouter(prefix="/api/kiwoom", tags=["kiwoom"])
DOMAINS = {"real": "https://api.kiwoom.com", "mock": "https://mockapi.kiwoom.com"}
# 키움은 API마다 초당 호출 수가 정해져 있음 (kt00018 = 1초 1회). 호출 간격을 지키고 결과를 잠시 재사용.
GAP = 1.2
_last_call = {"t": 0.0}
_cache: dict = {"at": 0.0, "data": None}
CACHE_SEC = 60


def _env() -> str:
    return "mock" if config.KIWOOM_ENV in ("mock", "paper", "모의") else "real"


def configured() -> bool:
    return bool(config.KIWOOM_APP_KEY and config.KIWOOM_SECRET)


def _fail(msg: str, status: int = 502):
    raise HTTPException(status, msg)


def _n(v) -> float:
    """키움 숫자는 '+000000012345' 같은 부호·0 채움 문자열."""
    try:
        return float(str(v or "0").replace(",", "").strip() or 0)
    except ValueError:
        return 0.0


def _token(db: DB, force: bool = False) -> str:
    key = f"kiwoom_token:{_env()}"
    saved = kv_get(db, key) or {}
    if not force and saved.get("token") and saved.get("exp", 0) > time.time() + 300:
        return saved["token"]
    body = json.dumps({"grant_type": "client_credentials", "appkey": config.KIWOOM_APP_KEY, "secretkey": config.KIWOOM_SECRET}).encode()
    try:
        _, _, text = http("POST", DOMAINS[_env()] + "/oauth2/token", {"Content-Type": "application/json;charset=UTF-8", "api-id": "au10001"}, body)
    except HttpError as e:
        _fail(f"키움 토큰 발급 실패 ({e.status}): {e.body[:200]}")
    try:
        data = json.loads(text)
    except ValueError:
        _fail("키움 토큰 응답을 읽지 못했습니다.")
    tok = data.get("token")
    if not tok:
        _fail(f"키움 토큰 응답 오류: {data.get('return_msg') or text[:200]}")
    exp = time.time() + 20 * 3600
    try:
        exp = datetime.strptime(str(data.get("expires_dt")), "%Y%m%d%H%M%S").replace(tzinfo=timezone(timedelta(hours=9))).timestamp()
    except ValueError:
        pass
    kv_set(db, key, {"token": tok, "exp": exp})
    return tok


def _wait() -> None:
    gap = time.time() - _last_call["t"]
    if gap < GAP:
        time.sleep(GAP - gap)
    _last_call["t"] = time.time()


def _post(db: DB, api_id: str, body: dict, cont: str = "N", next_key: str = "") -> tuple[dict, dict]:
    for attempt in (0, 1, 2):
        _wait()
        h = {"Content-Type": "application/json;charset=UTF-8", "authorization": f"Bearer {_token(db, attempt == 1)}",
             "api-id": api_id, "cont-yn": cont, "next-key": next_key}
        try:
            _, hd, text = http("POST", DOMAINS[_env()] + "/api/dostk/acnt", h, json.dumps(body).encode())
        except HttpError as e:
            if attempt == 0 and e.status in (401, 403):
                continue
            if e.status == 429 and attempt < 2:  # 초당 호출 한도 — 잠깐 쉬고 다시
                time.sleep(1.5 * (attempt + 1))
                continue
            if e.status == 429:
                _fail("키움 호출 한도(초당 1회)에 걸렸습니다. 1분쯤 뒤에 다시 눌러 주세요.", 429)
            _fail(f"키움 조회 실패 ({e.status}): {e.body[:200]}")
        data = json.loads(text)
        if str(data.get("return_code", "0")) not in ("0", ""):
            if attempt == 0 and "토큰" in str(data.get("return_msg", "")):
                continue
            _fail(f"키움 응답 오류 [{data.get('return_code')}] {data.get('return_msg', '')}")
        return data, hd
    _fail("키움 토큰을 다시 받았지만 조회에 실패했습니다.")


def fetch_balance(db: DB, fresh: bool = False) -> dict:
    if not configured():
        _fail("키움 REST API가 설정되지 않았습니다. .env의 KIWOOM_APP_KEY·KIWOOM_SECRET을 채우세요.", 400)
    if _cache["data"] and not fresh and time.time() - _cache["at"] < CACHE_SEC:
        return _cache["data"]
    holdings, top, cont, nk = [], {}, "N", ""
    for _ in range(10):
        data, hd = _post(db, "kt00018", {"qry_tp": "1", "dmst_stex_tp": "KRX"}, cont, nk)
        top = data
        for it in data.get("acnt_evlt_remn_indv_tot") or []:
            q = _n(it.get("rmnd_qty"))
            if q <= 0:
                continue
            holdings.append({"code": str(it.get("stk_cd", "")).lstrip("A"), "name": it.get("stk_nm"), "qty": q, "avg": _n(it.get("pur_pric")),
                             "price": abs(_n(it.get("cur_prc"))), "buy": _n(it.get("pur_amt")), "amount": _n(it.get("evlt_amt")),
                             "pl": _n(it.get("evltv_prft")), "plRate": _n(it.get("prft_rt"))})
        if str(hd.get("cont-yn", "N")).upper() == "Y" and hd.get("next-key"):
            cont, nk = "Y", hd.get("next-key")
            continue
        break
    summary = {"buyTotal": _n(top.get("tot_pur_amt")), "stockEval": _n(top.get("tot_evlt_amt")), "pl": _n(top.get("tot_evlt_pl")),
               "plRate": _n(top.get("tot_prft_rt")), "evalTotal": _n(top.get("prsm_dpst_aset_amt")) or _n(top.get("tot_evlt_amt"))}
    out = {"env": _env(), "asOf": datetime.now(timezone.utc).isoformat(), "summary": summary, "holdings": holdings}
    _cache.update(at=time.time(), data=out)
    return out


def sync_account(db: DB) -> int:
    data = fetch_balance(db)
    if data["env"] != "real":
        _fail("모의투자 잔고는 총자산에 넣지 않습니다.", 400)
    total = int(data["summary"]["evalTotal"])
    payload = {"inst": "키움증권", "alias": "자동 조회 (REST API)", "type": "증권", "last4": "", "balance": total,
               "checked": datetime.now().strftime("%Y-%m-%d"), "memo": "키움 REST API 자동 반영 (추정예탁자산)", "auto": "kiwoom"}
    rec = db.get(Record, "kiwoom_auto")
    if rec:
        rec.data = payload
        rec.updated_at = now()
    else:
        db.add(Record(id="kiwoom_auto", kind="fin_account", entity="personal", data=payload))
    db.commit()
    kv_set(db, "kiwoom_last", {"at": data["asOf"], "total": total})
    kv_set(db, "kiwoom_hold", {"at": data["asOf"], "holdings": data["holdings"]})
    return total


@router.get("/status")
def status(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    return {"configured": configured(), "env": _env(), "lastSync": (kv_get(db, "kiwoom_last") or {}).get("at")}


@router.get("/balance")
def balance(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    return fetch_balance(db)


@router.get("/holdings")
def holdings(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    return kv_get(db, "kiwoom_hold") or {}


@router.post("/sync")
def sync(req: Request, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    total = sync_account(db)
    audit(db, s.user_id, "kiwoom_sync", str(total), client_ip(req))
    return {"ok": True, "total": total}
