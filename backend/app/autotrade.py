"""한국투자증권 자동매매 — 전략 실행기와 안전장치.

안전장치 (모두 서버에서 검사):
1. 실행 모드: off(꺼짐) / dry(모의 실행: 주문은 안 내고 기록만) / live(실주문).
   live는 .env의 AUTOTRADE_LIVE=true + 비밀번호 재확인 후에만 켤 수 있음. 기본은 off.
2. 1회 주문 한도·하루 매수 한도(원). 넘으면 주문하지 않고 '거부'로 기록.
3. 평일 09:05~15:15(한국시간)에만 자동 실행. 휴장일은 증권사가 주문을 거부함.
4. 전략마다 하루 매수 1번·매도 1번까지만.
5. 국내주식 현금 매수·매도만 (신용·해외·선물 없음).
전략: 적립식(정해진 요일·시각에 정액 매수), 이동평균 교차(골든크로스 매수·데드크로스 전량 매도),
      목표가(지정가 이하 매수, 목표가·익절%·손절% 도달 시 전량 매도).
이 코드는 도구일 뿐이며 수익을 보장하지 않습니다.
"""
import math
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session as DB

from . import config, kis
from .db import get_db
from .kvstore import kv_get, kv_set
from .models import Record, Session
from .security import audit, client_ip, recent_reauth, require_user

router = APIRouter(prefix="/api/autotrade", tags=["autotrade"])
KST = timezone(timedelta(hours=9))
DAYS = "월화수목금토일"
DEFAULT = {"mode": "off", "perOrder": 300000, "daily": 1000000, "acct": 1}


def kst() -> datetime:
    return datetime.now(KST)


def settings(db: DB) -> dict:
    return {**DEFAULT, **(kv_get(db, "autotrade") or {})}


def market_open(t: datetime | None = None) -> bool:
    t = t or kst()
    hm = t.hour * 100 + t.minute
    return t.weekday() < 5 and 905 <= hm <= 1515


def _logs_today(db: DB) -> list[Record]:
    start = kst().replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc)
    return db.query(Record).filter(Record.kind == "at_log", Record.created_at >= start).all()


def bought_today(db: DB) -> int:
    return int(sum(float(r.data.get("amount") or 0) for r in _logs_today(db)
                   if r.data.get("side") == "buy" and r.data.get("result") in ("주문", "모의")))


def log(db: DB, **d) -> dict:
    t = kst()
    data = {"date": t.strftime("%Y-%m-%d"), "time": t.strftime("%H:%M:%S"), **d}
    db.add(Record(kind="at_log", entity="personal", data=data))
    db.commit()
    return data


def execute(db: DB, side: str, code: str, qty: int, est_price: float, why: str, sid: str = "", name: str = "", manual: bool = False) -> dict:
    """모든 주문은 여기를 거침. 모드·한도 검사 후 주문(또는 모의 기록)."""
    st = settings(db)
    base = {"sid": sid, "name": name or "수동 주문", "code": code, "side": side, "qty": qty, "price": est_price,
            "amount": round(qty * est_price), "why": why, "mode": st["mode"]}
    if qty <= 0:
        return log(db, **base, result="건너뜀", msg="수량 0 (금액이 1주 가격보다 작거나 보유 수량 없음)")
    if st["mode"] == "off" and not manual:
        return log(db, **base, result="건너뜀", msg="자동매매 꺼짐")
    if side == "buy":
        if base["amount"] > int(st["perOrder"]):
            return log(db, **base, result="거부", msg=f"1회 한도 {int(st['perOrder']):,}원 초과")
        if bought_today(db) + base["amount"] > int(st["daily"]):
            return log(db, **base, result="거부", msg=f"하루 매수 한도 {int(st['daily']):,}원 초과")
    live = st["mode"] == "live" and config.AUTOTRADE_LIVE
    if not live:
        return log(db, **base, result="모의", msg="모의 실행 — 실제 주문은 나가지 않았습니다")
    try:
        r = kis.order_cash(db, side, code, qty, 0, int(st.get("acct") or 1))
        return log(db, **base, result="주문", odno=r["odno"], msg=r["msg"])
    except HTTPException as e:
        return log(db, **base, result="오류", msg=str(e.detail)[:300])


def _holding(db: DB, code: str, idx: int) -> dict:
    for h in kis.fetch_domestic(db, kis.get_acct(idx))["holdings"]:
        if h["code"] == code:
            return h
    return {"qty": 0, "avg": 0}


def _done(db: DB, sid: str, side: str) -> bool:
    return bool(kv_get(db, f"at_done:{sid}:{kst():%Y%m%d}:{side}"))


def _mark(db: DB, sid: str, side: str) -> None:
    kv_set(db, f"at_done:{sid}:{kst():%Y%m%d}:{side}", 1)


def _sma(vals: list[float], n: int) -> float:
    return sum(vals[-n:]) / n if len(vals) >= n else 0.0


def run_strategy(db: DB, r: Record, force: bool = False) -> list[dict]:
    """전략 하나를 한 번 평가. force=True는 '지금 한 번 실행'(시각·요일 조건 무시, 하루 1회 제한은 유지)."""
    d, sid, out = r.data or {}, r.id, []
    code = str(d.get("code") or "").strip()
    if not (code.isdigit() and len(code) == 6):
        return [log(db, sid=sid, name=d.get("name"), code=code, side="-", qty=0, price=0, amount=0, result="오류", msg="종목코드가 6자리 숫자가 아닙니다", mode=settings(db)["mode"])]
    idx = int(settings(db).get("acct") or 1)
    t, typ, amount = kst(), d.get("type"), float(d.get("amount") or 0)
    hm = t.strftime("%H:%M")
    days = str(d.get("days") or "매일")
    day_ok = "매일" in days or DAYS[t.weekday()] in days
    at_time = str(d.get("time") or ("15:00" if typ == "이동평균 교차" else "09:10"))
    if typ == "적립식":
        if not force and (not day_ok or hm < at_time):
            return out
        if _done(db, sid, "buy"):
            return out
        p = kis.price(db, code, idx)["price"]
        out.append(execute(db, "buy", code, math.floor(amount / p) if p else 0, p, f"적립식 {days} {at_time}", sid, d.get("name")))
        _mark(db, sid, "buy")
    elif typ == "이동평균 교차":
        if not force and (not day_ok or hm < at_time):
            return out
        if _done(db, sid, "eval"):
            return out
        _mark(db, sid, "eval")
        s, l = int(d.get("short") or 5), int(d.get("long") or 20)
        closes = [c for _, c in kis.daily_closes(db, code, idx)]
        if len(closes) < l + 1:
            out.append(log(db, sid=sid, name=d.get("name"), code=code, side="-", qty=0, price=0, amount=0, result="건너뜀", msg=f"종가 {len(closes)}일치뿐이라 {l}일 평균을 못 냄", mode=settings(db)["mode"]))
            return out
        ps, pl, ns, nl = _sma(closes[:-1], s), _sma(closes[:-1], l), _sma(closes, s), _sma(closes, l)
        p = closes[-1]
        if ps <= pl and ns > nl:
            out.append(execute(db, "buy", code, math.floor(amount / p) if p else 0, p, f"골든크로스 {s}/{l}일 ({ns:,.0f}>{nl:,.0f})", sid, d.get("name")))
        elif ps >= pl and ns < nl:
            h = _holding(db, code, idx)
            out.append(execute(db, "sell", code, int(h["qty"]), p, f"데드크로스 {s}/{l}일 ({ns:,.0f}<{nl:,.0f})", sid, d.get("name")))
        else:
            out.append(log(db, sid=sid, name=d.get("name"), code=code, side="-", qty=0, price=p, amount=0, result="신호 없음",
                           msg=f"{s}일 {ns:,.0f} / {l}일 {nl:,.0f}", mode=settings(db)["mode"]))
    elif typ == "목표가":
        if not force:
            last = kv_get(db, f"at_chk:{sid}") or 0
            if t.timestamp() - float(last) < 180:  # 3분에 한 번만 시세 확인
                return out
            kv_set(db, f"at_chk:{sid}", t.timestamp())
        p = kis.price(db, code, idx)["price"]
        h = _holding(db, code, idx)
        buy_below, sell_above = float(d.get("buyBelow") or 0), float(d.get("sellAbove") or 0)
        tp, sl = float(d.get("takeProfit") or 0), float(d.get("stopLoss") or 0)
        if h["qty"] > 0 and not _done(db, sid, "sell"):
            why = ""
            if sell_above and p >= sell_above:
                why = f"목표가 {sell_above:,.0f} 도달"
            elif tp and h["avg"] and p >= h["avg"] * (1 + tp / 100):
                why = f"익절 +{tp}% (평단 {h['avg']:,.0f})"
            elif sl and h["avg"] and p <= h["avg"] * (1 - sl / 100):
                why = f"손절 -{sl}% (평단 {h['avg']:,.0f})"
            if why:
                out.append(execute(db, "sell", code, int(h["qty"]), p, why, sid, d.get("name")))
                _mark(db, sid, "sell")
        if buy_below and p <= buy_below and not _done(db, sid, "buy"):
            max_qty = int(d.get("maxQty") or 0)
            q = math.floor(amount / p) if p else 0
            if max_qty:
                q = max(0, min(q, max_qty - int(h["qty"])))
            out.append(execute(db, "buy", code, q, p, f"매수가 {buy_below:,.0f} 이하", sid, d.get("name")))
            _mark(db, sid, "buy")
        if force and not out:
            out.append(log(db, sid=sid, name=d.get("name"), code=code, side="-", qty=0, price=p, amount=0, result="신호 없음",
                           msg=f"현재가 {p:,.0f} · 보유 {int(h['qty'])}주", mode=settings(db)["mode"]))
    return out


def tick(db: DB) -> None:
    """스케줄러가 1분마다 부름."""
    st = settings(db)
    if st["mode"] == "off" or not kis.configured() or not market_open():
        return
    for r in db.query(Record).filter(Record.kind == "at_strategy").all():
        if (r.data or {}).get("enabled") != "켜짐":
            continue
        try:
            run_strategy(db, r)
        except HTTPException as e:
            db.rollback()
            if not _done(db, r.id, "err"):  # 같은 오류로 기록이 도배되지 않게 하루 1번만 남김
                log(db, sid=r.id, name=r.data.get("name"), code=r.data.get("code"), side="-", qty=0, price=0, amount=0,
                    result="오류", msg=str(e.detail)[:300], mode=st["mode"])
                _mark(db, r.id, "err")


# ---------------- API ----------------
@router.get("/status")
def status(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    st = settings(db)
    return {**st, "liveAllowed": config.AUTOTRADE_LIVE, "configured": kis.configured(), "marketOpen": market_open(),
            "boughtToday": bought_today(db), "now": kst().strftime("%Y-%m-%d %H:%M"),
            "accounts": [{"idx": a.idx, "name": a.name, "env": a.env, "account": a.masked} for a in kis.accounts()]}


@router.post("/settings")
def save_settings(req: Request, body: dict = Body(...), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    st = settings(db)
    mode = body.get("mode", st["mode"])
    if mode not in ("off", "dry", "live"):
        raise HTTPException(400, "모드 값이 올바르지 않습니다.")
    if mode == "live":
        if not config.AUTOTRADE_LIVE:
            raise HTTPException(400, "실주문은 NAS .env에 AUTOTRADE_LIVE=true를 넣고 sudo docker compose up -d 한 뒤에만 켤 수 있습니다.")
        if not recent_reauth(s):
            raise HTTPException(403, "reauth_required")
    try:
        per, daily = int(body.get("perOrder", st["perOrder"])), int(body.get("daily", st["daily"]))
    except (TypeError, ValueError):
        raise HTTPException(400, "한도는 숫자로 입력하세요.")
    if per <= 0 or daily <= 0 or per > daily:
        raise HTTPException(400, "한도는 0보다 크고, 1회 한도는 하루 한도보다 작아야 합니다.")
    new = {"mode": mode, "perOrder": per, "daily": daily, "acct": int(body.get("acct", st["acct"]) or 1)}
    kv_set(db, "autotrade", new)
    audit(db, s.user_id, "autotrade_settings", f"{mode} {per}/{daily}", client_ip(req))
    return new


@router.post("/run/{sid}")
def run_now(sid: str, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    r = db.get(Record, sid)
    if not r or r.kind != "at_strategy":
        raise HTTPException(404, "전략을 찾을 수 없습니다.")
    if settings(db)["mode"] == "live" and not market_open():
        raise HTTPException(400, "실주문 모드에서는 장 시간(평일 09:05~15:15)에만 실행할 수 있습니다.")
    res = run_strategy(db, r, force=True)
    return {"results": res or [{"result": "건너뜀", "msg": "오늘 이미 실행했습니다 (전략마다 하루 매수·매도 각 1번)"}]}


@router.post("/order")
def manual_order(req: Request, body: dict = Body(...), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """수동 주문. 모드가 live일 때만 실제 주문, 그 외에는 모의 기록. 항상 비밀번호 재확인 필요."""
    if not recent_reauth(s):
        raise HTTPException(403, "reauth_required")
    side, code = body.get("side"), str(body.get("code") or "").strip()
    if side not in ("buy", "sell") or not (code.isdigit() and len(code) == 6):
        raise HTTPException(400, "매수/매도와 6자리 종목코드를 확인하세요.")
    try:
        qty = int(body.get("qty") or 0)
    except (TypeError, ValueError):
        raise HTTPException(400, "수량은 정수로 입력하세요.")
    p = kis.price(db, code, int(settings(db).get("acct") or 1))["price"]
    res = execute(db, side, code, qty, p, "수동 주문 (시장가)", manual=True)
    audit(db, s.user_id, "autotrade_manual", f"{side} {code} {qty} -> {res['result']}", client_ip(req))
    return res
