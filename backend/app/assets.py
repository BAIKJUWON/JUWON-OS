"""자산 스냅샷 — 그 시점의 총자산을 계산해 기록으로 남김 (화면 버튼 + 매월 1일 자동)."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends
from sqlalchemy.orm import Session as DB

from .db import get_db
from .models import Record, Session
from .security import require_user

router = APIRouter(prefix="/api/assets", tags=["assets"])
KST = timezone(timedelta(hours=9))


def _n(v) -> float:
    try:
        return float(str(v).replace(",", "") or 0)
    except ValueError:
        return 0.0


def compute(db: DB) -> dict:
    recs = lambda k: [r.data or {} for r in db.query(Record).filter(Record.kind == k).all()]
    cash = invest = debt = 0.0
    for a in recs("fin_account"):
        b = _n(a.get("balance"))
        if b < 0:
            debt += -b
        elif a.get("type") in ("증권", "ISA", "연금"):
            invest += b
        else:
            cash += b
    for h in recs("inv_hold"):
        if h.get("inTotal", "포함") == "포함":
            invest += _n(h.get("qty")) * _n(h.get("price") or h.get("avg")) * (_n(h.get("fx")) or 1)
    real = 0.0
    for r in recs("re_asset"):
        real += _n(r.get("value")) if r.get("own") in ("자가", "자가(임대 중)") else _n(r.get("deposit"))
        debt += _n(r.get("loan"))
    for l in recs("loan"):
        debt += _n(l.get("remain"))
    total = cash + invest + real - debt
    return {"cash": round(cash), "invest": round(invest), "realestate": round(real), "debt": round(debt), "total": round(total)}


def save_snapshot(db: DB, memo: str = "") -> dict:
    v = compute(db)
    d = {"date": datetime.now(KST).strftime("%Y-%m-%d"), **v, "memo": memo}
    db.add(Record(kind="snapshot", entity="personal", data=d))
    db.commit()
    return d


@router.get("/now")
def now_value(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    return compute(db)


@router.post("/snapshot")
def snapshot(body: dict = Body(default={}), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    return save_snapshot(db, str(body.get("memo") or "")[:200])
