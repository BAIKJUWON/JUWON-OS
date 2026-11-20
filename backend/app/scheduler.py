"""백그라운드 작업 (api 컨테이너 안에서 1분마다).

- 자동매매 전략 실행 (autotrade.tick)
- AUTO_SYNC_MINUTES마다 한국투자증권·키움 잔고 자동 불러오기 (07~23시). 은행·카드는 버튼으로만 조회
- 매월 1일 자산 스냅샷
여러 프로세스가 떠도 한 곳에서만 돌도록 PostgreSQL advisory lock을 잡습니다.
"""
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from . import autotrade, config, feeds, kis, kiwoom
from .assets import save_snapshot
from .db import SessionLocal, engine
from .kvstore import kv_get, kv_set

KST = timezone(timedelta(hours=9))
log = logging.getLogger("juwon.scheduler")
_started = False


def _auto_sync(db) -> None:
    st = kv_get(db, "auto_sync") or {}
    if time.time() - float(st.get("ts", 0)) < config.AUTO_SYNC_MINUTES * 60:
        return
    res, errs = [], []
    for a in kis.accounts():
        if a.env != "real":
            continue
        try:
            res.append(f"{a.name} {kis.sync_account(db, a.idx):,}원")
        except Exception as e:  # noqa: BLE001
            db.rollback()
            errs.append(f"{a.name}: {getattr(e, 'detail', e)}")
    if kiwoom.configured():
        try:
            res.append(f"키움 {kiwoom.sync_account(db):,}원")
        except Exception as e:  # noqa: BLE001
            db.rollback()
            errs.append(f"키움: {getattr(e, 'detail', e)}")
    # 은행·카드(CODEF)는 자동으로 수집하지 않습니다 — 화면의 '불러오기' 버튼을 눌렀을 때만 조회 (v0.11)
    kv_set(db, "auto_sync", {"ts": time.time(), "at": datetime.now(KST).strftime("%Y-%m-%d %H:%M"), "done": res, "errors": [str(x)[:200] for x in errs]})


def _loop() -> None:
    conn = engine.connect()
    got = conn.execute(text("SELECT pg_try_advisory_lock(7710442)")).scalar()
    if not got:
        log.info("다른 프로세스가 스케줄러를 돌리고 있어 이 프로세스는 건너뜁니다")
        conn.close()
        return
    conn.commit()  # 잠금은 세션 단위라 트랜잭션을 닫아도 유지됨
    while True:
        t = datetime.now(KST)
        db = SessionLocal()
        try:
            autotrade.tick(db)
        except Exception:  # noqa: BLE001
            db.rollback()
            log.exception("자동매매 실행 오류")
        try:
            if config.AUTO_SYNC_MINUTES > 0 and 7 <= t.hour < 23:
                _auto_sync(db)
        except Exception:  # noqa: BLE001
            db.rollback()
            log.exception("자동 불러오기 오류")
        try:
            if 7 <= t.hour < 24:
                feeds.maybe_refresh(db)
        except Exception:  # noqa: BLE001
            db.rollback()
            log.exception("소식 수집 오류")
        try:
            if t.day == 1 and t.hour >= 6 and (kv_get(db, "snap_month") or "") != t.strftime("%Y-%m"):
                save_snapshot(db, "매월 1일 자동 기록")
                kv_set(db, "snap_month", t.strftime("%Y-%m"))
        except Exception:  # noqa: BLE001
            db.rollback()
            log.exception("스냅샷 오류")
        finally:
            db.close()
        conn.execute(text("SELECT 1"))  # 잠금 연결 유지
        conn.commit()
        time.sleep(60 - datetime.now().second % 60 or 60)


def start() -> None:
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, name="juwon-scheduler", daemon=True).start()
