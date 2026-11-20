"""한국투자증권 KIS Developers Open API — 잔고(국내·해외/미니스탁) 조회, 시세, 현금 주문.

- 계좌는 최대 2개 (KIS_* = 1번, KIS2_* = 2번). 앱키는 계좌마다 따로 발급되므로 미니스탁을 다른 계좌번호로 쓰면 2번에 넣습니다.
- 주문 함수(order_cash)는 autotrade.py에서만 부르고, 거기서 실주문 허용 여부·한도를 검사합니다.
경로·tr_id는 KIS Developers 문서 기준입니다. 증권사가 바꿀 수 있으니 오류 메시지의 msg_cd로 문서를 대조하세요.
"""
import json
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session as DB

from . import config
from .db import get_db
from .kvstore import HttpError, http, kv_get, kv_set
from .models import Record, Session, now
from .security import audit, client_ip, require_user

router = APIRouter(prefix="/api/kis", tags=["kis"])

DOMAINS = {"real": "https://openapi.koreainvestment.com:9443", "paper": "https://openapivts.koreainvestment.com:29443"}
TR = {
    "balance": {"real": "TTTC8434R", "paper": "VTTC8434R"},
    "overseas": {"real": "CTRP6504R", "paper": "VTRP6504R"},   # 해외주식 체결기준현재잔고 (INQR_DVSN_CD 00 = 일반+미니스탁)
    "buy": {"real": "TTTC0012U", "paper": "VTTC0012U"},
    "sell": {"real": "TTTC0011U", "paper": "VTTC0011U"},
}
MARKET = {"NASD": "미국", "NYSE": "미국", "AMEX": "미국", "NAS": "미국", "SEHK": "홍콩", "SHAA": "중국", "SZAA": "중국",
          "TKSE": "일본", "HASE": "베트남", "VNSE": "베트남"}
_cache: dict = {}


@dataclass
class Acct:
    idx: int
    name: str
    env: str
    key: str
    secret: str
    cano: str
    prod: str

    @property
    def ok(self) -> bool:
        return bool(self.key and self.secret and len(self.cano) == 8)

    @property
    def masked(self) -> str:
        return (self.cano[:2] + "****" + self.cano[-2:] + "-" + self.prod) if len(self.cano) == 8 else ""

    @property
    def rec_id(self) -> str:
        return "kis_auto" if self.idx == 1 else f"kis_auto_{self.idx}"


def _envname(v: str) -> str:
    return "paper" if v in ("paper", "모의", "vts", "mock") else "real"


def accounts() -> list[Acct]:
    out = [Acct(1, "한국투자증권", _envname(config.KIS_ENV), config.KIS_APP_KEY, config.KIS_APP_SECRET, config.KIS_ACCOUNT, config.KIS_ACCOUNT_PROD),
           Acct(2, config.KIS2_NAME or "한국투자증권 2", _envname(config.KIS2_ENV), config.KIS2_APP_KEY, config.KIS2_APP_SECRET, config.KIS2_ACCOUNT, config.KIS2_ACCOUNT_PROD)]
    return [a for a in out if a.ok]


def get_acct(idx: int = 1) -> Acct:
    for a in accounts():
        if a.idx == idx:
            return a
    _fail("한국투자증권 API가 설정되지 않았습니다. .env의 KIS_APP_KEY·KIS_APP_SECRET·KIS_ACCOUNT(앞 8자리)를 채우세요.", 400)


def configured() -> bool:
    return bool(accounts())


def _fail(msg: str, status: int = 502):
    raise HTTPException(status, msg)


def _token(db: DB, a: Acct, force: bool = False) -> str:
    """접근 토큰은 하루 유효하고 자주 발급하면(1분 1회) 제한이 걸리므로 DB에 저장해 재사용합니다."""
    key = f"kis_token:{a.idx}:{a.env}"
    saved = kv_get(db, key) or {}
    if not force and saved.get("token") and saved.get("exp", 0) > time.time() + 300 and saved.get("k") == a.key[:6]:
        return saved["token"]
    body = json.dumps({"grant_type": "client_credentials", "appkey": a.key, "appsecret": a.secret}).encode()
    try:
        _, _, text = http("POST", DOMAINS[a.env] + "/oauth2/tokenP", {"content-type": "application/json; charset=utf-8"}, body)
    except HttpError as e:
        hint = " (실전 앱키면 KIS_ENV=real, 모의투자 앱키면 KIS_ENV=paper)" if "EGW02007" in e.body or "EGW00103" in e.body else ""
        _fail(f"{a.name} 토큰 발급 실패 ({e.status}){hint}: {e.body[:200]}")
    try:
        data = json.loads(text)
    except ValueError:
        _fail(f"{a.name} 토큰 응답을 읽지 못했습니다.")
    tok = data.get("access_token")
    if not tok:
        _fail(f"{a.name} 토큰 응답에 토큰이 없습니다: {text[:200]}")
    kv_set(db, key, {"token": tok, "k": a.key[:6], "exp": time.time() + int(data.get("expires_in", 86400))})
    return tok


def _headers(db: DB, a: Acct, tr_id: str, force: bool = False, tr_cont: str = "") -> dict:
    return {"content-type": "application/json; charset=utf-8", "authorization": f"Bearer {_token(db, a, force)}",
            "appkey": a.key, "appsecret": a.secret, "tr_id": tr_id, "custtype": "P", "tr_cont": tr_cont}


def _parse(text: str, a: Acct) -> dict:
    try:
        return json.loads(text)
    except ValueError:
        _fail(f"{a.name} 응답을 읽지 못했습니다: {text[:120]}")


def kis_get(db: DB, a: Acct, path: str, tr_id: str, params: dict, tr_cont: str = "") -> tuple[dict, dict]:
    for attempt in (0, 1):
        url = DOMAINS[a.env] + path + "?" + urllib.parse.urlencode(params)
        try:
            _, h, text = http("GET", url, _headers(db, a, tr_id, attempt == 1, tr_cont))
        except HttpError as e:
            if attempt == 0 and ("EGW00123" in e.body or "EGW00121" in e.body):  # 토큰 만료·무효
                continue
            _fail(f"{a.name} 조회 실패 ({e.status}): {e.body[:200]}")
        data = _parse(text, a)
        if str(data.get("rt_cd")) != "0":
            if attempt == 0 and data.get("msg_cd") in ("EGW00123", "EGW00121"):
                continue
            _fail(f"{a.name} 응답 오류 [{data.get('msg_cd')}] {data.get('msg1', '')}")
        return data, h
    _fail(f"{a.name} 토큰을 다시 받았지만 조회에 실패했습니다.")


def kis_post(db: DB, a: Acct, path: str, tr_id: str, body: dict) -> dict:
    raw = json.dumps(body).encode()
    h = _headers(db, a, tr_id)
    try:  # 주문은 hashkey를 함께 보냄 (실패해도 주문 자체는 진행 — 현재는 선택 항목)
        _, _, ht = http("POST", DOMAINS[a.env] + "/uapi/hashkey", {"content-type": "application/json; charset=utf-8", "appkey": a.key, "appsecret": a.secret}, raw)
        hk = json.loads(ht).get("HASH")
        if hk:
            h["hashkey"] = hk
    except Exception:
        pass
    try:
        _, _, text = http("POST", DOMAINS[a.env] + path, h, raw)
    except HttpError as e:
        _fail(f"{a.name} 주문 요청 실패 ({e.status}): {e.body[:200]}")
    data = _parse(text, a)
    if str(data.get("rt_cd")) != "0":
        _fail(f"{a.name} 주문 거부 [{data.get('msg_cd')}] {data.get('msg1', '')}")
    return data


def _num(v) -> float:
    try:
        return float(str(v).replace(",", "").strip() or 0)
    except ValueError:
        return 0.0


def _pick(d: dict, *keys) -> float:
    for k in keys:
        if d.get(k) not in (None, ""):
            return _num(d.get(k))
    return 0.0


# ---------------- 잔고 ----------------
def fetch_domestic(db: DB, a: Acct) -> dict:
    params = {"CANO": a.cano, "ACNT_PRDT_CD": a.prod, "AFHR_FLPR_YN": "N", "OFL_YN": "", "INQR_DVSN": "02", "UNPR_DVSN": "01",
              "FUND_STTL_ICLD_YN": "N", "FNCG_AMT_AUTO_RDPT_YN": "N", "PRCS_DVSN": "00", "CTX_AREA_FK100": "", "CTX_AREA_NK100": ""}
    holdings, summary, tr_cont = [], {}, ""
    for _ in range(10):
        data, h = kis_get(db, a, "/uapi/domestic-stock/v1/trading/inquire-balance", TR["balance"][a.env], params, tr_cont)
        for it in data.get("output1") or []:
            if _num(it.get("hldg_qty")) <= 0:
                continue
            holdings.append({"code": it.get("pdno"), "name": it.get("prdt_name"), "qty": _num(it.get("hldg_qty")),
                             "avg": _num(it.get("pchs_avg_pric")), "price": _num(it.get("prpr")), "buy": _num(it.get("pchs_amt")),
                             "amount": _num(it.get("evlu_amt")), "pl": _num(it.get("evlu_pfls_amt")), "plRate": _num(it.get("evlu_pfls_rt"))})
        o2 = data.get("output2") or []
        if isinstance(o2, dict):
            o2 = [o2]
        if o2:
            s = o2[0]
            summary = {"cash": _num(s.get("dnca_tot_amt")), "stockEval": _num(s.get("scts_evlu_amt")), "evalTotal": _num(s.get("tot_evlu_amt")),
                       "buyTotal": _num(s.get("pchs_amt_smtl_amt")), "pl": _num(s.get("evlu_pfls_smtl_amt")), "net": _num(s.get("nass_amt"))}
        if h.get("tr_cont") in ("F", "M"):
            params["CTX_AREA_FK100"] = data.get("ctx_area_fk100", "")
            params["CTX_AREA_NK100"] = data.get("ctx_area_nk100", "")
            tr_cont = "N"
            continue
        break
    return {"holdings": holdings, "summary": summary}


def fetch_overseas(db: DB, a: Acct) -> dict:
    """해외주식 잔고. INQR_DVSN_CD=00(전체)이라 일반 해외주식과 미니스탁(소수점)을 함께 가져옵니다.
    WCRC_FRCR_DVSN_CD=01(원화)로 조회하므로 응답의 단가·금액은 이미 '원화 환산값'입니다.
    이전 버전은 이 값을 외화(USD)로 착각해 환율을 한 번 더 곱했고, 그래서 잔액이 천 배 넘게 뻥튀기됐습니다 — 수정."""
    params = {"CANO": a.cano, "ACNT_PRDT_CD": a.prod, "WCRC_FRCR_DVSN_CD": "01", "NATN_CD": "000", "TR_MKET_CD": "00", "INQR_DVSN_CD": "00"}
    data, _ = kis_get(db, a, "/uapi/overseas-stock/v1/trading/inquire-present-balance", TR["overseas"][a.env], params)
    rows = []
    out1 = data.get("output1") or []
    if isinstance(out1, dict):
        out1 = [out1]
    for it in out1:
        qty = _pick(it, "cblc_qty13", "ccld_qty_smtl1", "ovrs_cblc_qty", "hldg_qty")
        if qty <= 0:
            continue
        rate = _pick(it, "bass_exrt", "frst_bltn_exrt")
        avg_krw = _pick(it, "avg_unpr3", "pchs_avg_pric")          # 1주당 매입가 (원화 환산)
        price_krw = _pick(it, "ovrs_now_pric1", "now_pric2")       # 1주당 현재가 (원화 환산)
        eval_krw = _pick(it, "frcr_evlu_amt2", "ovrs_stck_evlu_amt", "frcr_evlu_amt") or qty * price_krw
        buy_krw = _pick(it, "frcr_pchs_amt1", "frcr_pchs_amt") or qty * avg_krw
        pl_krw = _pick(it, "evlu_pfls_amt2", "frcr_evlu_pfls_amt", "evlu_pfls_amt") or (eval_krw - buy_krw)
        fx = (lambda v: round(v / rate, 2) if rate else 0.0)       # 외화 표시용 (기준환율로 역산)
        rows.append({"code": it.get("pdno") or it.get("ovrs_pdno"), "name": it.get("prdt_name") or it.get("ovrs_item_name"),
                     "market": MARKET.get(it.get("ovrs_excg_cd") or "", it.get("ovrs_excg_cd") or ""), "currency": it.get("buy_crcy_cd") or "USD",
                     "qty": qty, "avg": fx(avg_krw), "price": fx(price_krw), "fxEval": fx(eval_krw), "fxPl": fx(pl_krw), "rate": rate,
                     "avgKrw": round(avg_krw), "priceKrw": round(price_krw),
                     "evalKrw": round(eval_krw), "buyKrw": round(buy_krw), "plKrw": round(pl_krw),
                     "plRate": _pick(it, "evlu_pfls_rt1", "evlu_pfls_rt")})
    diag = ""
    if not rows:
        o2 = data.get("output2") or []
        o3 = data.get("output3") or {}
        diag = (f"응답: 종목 {len(out1)}줄(수량 0 제외 후 0), 통화별 요약 {len(o2) if isinstance(o2, list) else 1}줄, "
                f"합계 항목 {', '.join(list(o3.keys())[:6]) if isinstance(o3, dict) else '-'}. "
                "미니스탁이 이 계좌번호에 없으면 미니스탁 계좌의 앱키를 KIS2_* 칸에 넣으세요.")
    return {"holdings": rows, "evalKrw": sum(r["evalKrw"] for r in rows), "buyKrw": sum(r["buyKrw"] for r in rows),
            "plKrw": sum(r["plKrw"] for r in rows), "diag": diag}


def fetch_balance(db: DB, idx: int = 1, fresh: bool = False) -> dict:
    a = get_acct(idx)
    c = _cache.get(idx)
    if c and not fresh and time.time() - c["at"] < 30:
        return c["data"]
    dom = fetch_domestic(db, a)
    over, over_err = {"holdings": [], "evalKrw": 0, "buyKrw": 0, "plKrw": 0, "diag": ""}, ""
    try:
        over = fetch_overseas(db, a)
    except HTTPException as e:
        over_err = str(e.detail)
    summary = dom["summary"]
    summary["overseasEval"] = over["evalKrw"]
    summary["grandTotal"] = (summary.get("evalTotal") or 0) + over["evalKrw"]
    out = {"idx": a.idx, "name": a.name, "env": a.env, "account": a.masked, "asOf": datetime.now(timezone.utc).isoformat(),
           "summary": summary, "holdings": dom["holdings"], "overseas": over, "overseasError": over_err}
    _cache[idx] = {"at": time.time(), "data": out}
    return out


def sync_account(db: DB, idx: int) -> int:
    """평가금액 합계를 '은행·증권 계좌'에 반영. 실전 계좌만."""
    data = fetch_balance(db, idx, fresh=True)
    if data["env"] != "real":
        _fail("모의투자 잔고는 가짜 돈이라 총자산에 넣지 않습니다.", 400)
    a = get_acct(idx)
    total = int(data["summary"].get("grandTotal") or 0)
    payload = {"inst": "한국투자증권", "alias": f"{a.name} · 자동 조회", "type": "증권", "last4": a.cano[-4:], "balance": total,
               "checked": datetime.now().strftime("%Y-%m-%d"), "memo": "API 자동 반영 (국내 평가+예수금 + 해외·미니스탁 원화 환산)", "auto": "kis"}
    rec = db.get(Record, a.rec_id)
    if rec:
        rec.data = payload
        rec.updated_at = now()
    else:
        db.add(Record(id=a.rec_id, kind="fin_account", entity="personal", data=payload))
    db.commit()
    kv_set(db, f"kis_last:{idx}", {"at": data["asOf"], "total": total})
    # 투자 포트폴리오 화면에서 쓰도록 마지막 보유 종목을 저장
    kv_set(db, f"kis_hold:{idx}", {"at": data["asOf"], "holdings": data["holdings"], "overseas": data["overseas"]["holdings"]})
    return total


# ---------------- 시세 · 주문 ----------------
def price(db: DB, code: str, idx: int = 1) -> dict:
    a = get_acct(idx)
    data, _ = kis_get(db, a, "/uapi/domestic-stock/v1/quotations/inquire-price", "FHKST01010100",
                      {"FID_COND_MRKT_DIV_CODE": "J", "FID_INPUT_ISCD": code})
    o = data.get("output") or {}
    return {"code": code, "price": _num(o.get("stck_prpr")), "change": _num(o.get("prdy_ctrt")), "high": _num(o.get("stck_hgpr")),
            "low": _num(o.get("stck_lwpr")), "upper": _num(o.get("stck_mxpr")), "lower": _num(o.get("stck_llam"))}


def daily_closes(db: DB, code: str, idx: int = 1) -> list[tuple[str, float]]:
    """최근 30거래일 종가 (오래된 → 최근)."""
    a = get_acct(idx)
    data, _ = kis_get(db, a, "/uapi/domestic-stock/v1/quotations/inquire-daily-price", "FHKST01010400",
                      {"FID_COND_MRKT_DIV_CODE": "J", "FID_INPUT_ISCD": code, "FID_PERIOD_DIV_CODE": "D", "FID_ORG_ADJ_PRC": "1"})
    rows = [(r.get("stck_bsop_date", ""), _num(r.get("stck_clpr"))) for r in (data.get("output") or []) if _num(r.get("stck_clpr")) > 0]
    return sorted(rows)


def order_cash(db: DB, side: str, code: str, qty: int, price_won: int = 0, idx: int = 1) -> dict:
    """현금 주문. price_won=0이면 시장가. 반드시 autotrade.py의 안전장치를 거쳐서 부를 것."""
    a = get_acct(idx)
    body = {"CANO": a.cano, "ACNT_PRDT_CD": a.prod, "PDNO": code, "ORD_DVSN": "01" if price_won <= 0 else "00",
            "ORD_QTY": str(int(qty)), "ORD_UNPR": "0" if price_won <= 0 else str(int(price_won)), "EXCG_ID_DVSN_CD": "KRX",
            "SLL_TYPE": "01" if side == "sell" else "", "CNDT_PRIC": ""}
    data = kis_post(db, a, "/uapi/domestic-stock/v1/trading/order-cash", TR[side][a.env], body)
    out = data.get("output") or {}
    return {"odno": out.get("ODNO") or out.get("odno") or "", "msg": data.get("msg1", "")}


# ---------------- API ----------------
@router.get("/status")
def status(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    accts = accounts()
    return {"configured": bool(accts), "env": accts[0].env if accts else "real", "account": accts[0].masked if accts else "",
            "accounts": [{"idx": a.idx, "name": a.name, "env": a.env, "account": a.masked, "lastSync": (kv_get(db, f"kis_last:{a.idx}") or {}).get("at")} for a in accts],
            "lastSync": (kv_get(db, "kis_last:1") or {}).get("at"), "auto": kv_get(db, "auto_sync") or {}}


@router.get("/balance")
def balance(idx: int = 1, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    return fetch_balance(db, idx)


@router.get("/holdings")
def holdings(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """마지막으로 반영한 보유 종목 (투자 포트폴리오 화면용, 증권사 호출 없음)."""
    return {str(a.idx): {"name": a.name, **(kv_get(db, f"kis_hold:{a.idx}") or {})} for a in accounts()}


@router.get("/price/{code}")
def get_price(code: str, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    if not code.isdigit() or len(code) != 6:
        _fail("종목코드는 숫자 6자리입니다 (예: 005930).", 400)
    return price(db, code)


@router.post("/sync")
def sync(req: Request, idx: int = 0, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """실전 계좌 평가금액을 금융·자산의 '은행·증권 계좌'에 반영합니다. idx=0이면 설정된 모든 계좌."""
    targets = [a.idx for a in accounts() if (idx == 0 or a.idx == idx)]
    if not targets:
        get_acct(idx or 1)
    total, done, errs, last = 0, [], [], None
    for i in targets:
        try:
            total += sync_account(db, i)
            done.append(i)
        except HTTPException as e:
            errs.append(str(e.detail))
    if not done and errs:
        _fail(" / ".join(errs), 400)
    audit(db, s.user_id, "kis_sync", str(total), client_ip(req))
    last = _cache.get(done[0], {}).get("data") if done else None
    return {"ok": True, "total": total, "errors": errs, "balance": last}
