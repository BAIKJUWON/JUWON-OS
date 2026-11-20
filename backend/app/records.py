"""모든 화면이 쓰는 범용 기록 API.

응답은 화면에서 쓰기 쉽게 평평한 모양입니다:
  {"id", "kind", "createdAt", "updatedAt", ...필드, "fileId", "fileName", "fileUrl", ...}
"""
import hashlib
import json
import os
import re

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session as DB

from .db import get_db
from .files import delete_file_if_orphan, file_meta
from . import config
from .kinds import GATED, KINDS, MAX_DATA_BYTES, RESERVED
from .models import Record, Session, StoredFile, now
from .security import audit, client_ip, dec, enc, recent_reauth, require_user

router = APIRouter(prefix="/api", tags=["records"])
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def serialize(r: Record, f: StoredFile | None) -> dict:
    d = dict(r.data or {})
    for k in KINDS.get(r.kind, {}).get("secret", []):
        if isinstance(d.get(k), dict) and "enc" in d[k]:
            d[k] = dec(d[k]["enc"])
    d.update(id=r.id, kind=r.kind, createdAt=r.created_at.isoformat(), updatedAt=r.updated_at.isoformat())
    d.update(file_meta(f))
    return d


def _clean(kind: str, body: dict) -> dict:
    data = {k: v for k, v in body.items() if k not in RESERVED and not k.startswith("_")}
    for k in KINDS[kind].get("secret", []):
        if k in data and isinstance(data[k], str) and data[k]:
            data[k] = {"enc": enc(data[k])}
    if len(json.dumps(data, ensure_ascii=False).encode()) > MAX_DATA_BYTES:
        raise HTTPException(413, "기록 내용이 너무 큽니다.")
    return data


def _apply_file(db: DB, rec: Record, body: dict) -> StoredFile | None:
    """body.fileId가 오면 연결(교체 시 이전 파일 정리), 빈 문자열이면 연결 해제."""
    old = rec.file_id
    if "fileId" in body:
        fid = body.get("fileId") or None
        if fid and not db.get(StoredFile, fid):
            raise HTTPException(400, "unknown_file")
        rec.file_id = fid
    f = db.get(StoredFile, rec.file_id) if rec.file_id else None
    if f:
        rule = KINDS[rec.kind].get("vault")
        f.vault = bool(rule and rule(rec.data or {}))
    db.flush()
    if old and old != rec.file_id:
        db.commit()
        delete_file_if_orphan(db, old)
    return f


def _gate(kind: str, s: Session) -> None:
    if kind in GATED and not recent_reauth(s):
        raise HTTPException(403, "reauth_required")


@router.get("/records")
def list_records(kinds: str = "", s: Session = Depends(require_user), db: DB = Depends(get_db)):
    q = db.query(Record)
    if not recent_reauth(s):
        q = q.filter(Record.kind.notin_(GATED))  # 인감 목록은 비밀번호 재확인 뒤에만
    if kinds:
        ks = [k for k in kinds.split(",") if k in KINDS]
        q = q.filter(Record.kind.in_(ks))
    rows = q.order_by(Record.created_at.desc()).all()
    fids = {r.file_id for r in rows if r.file_id}
    files = {f.id: f for f in db.query(StoredFile).filter(StoredFile.id.in_(fids)).all()} if fids else {}
    return [serialize(r, files.get(r.file_id)) for r in rows]


@router.post("/records")
def create_record(body: dict = Body(...), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    kind = body.get("kind")
    if kind not in KINDS:
        raise HTTPException(400, "unknown_kind")
    _gate(kind, s)
    rid = body.get("id")
    if rid is not None and (not ID_RE.match(str(rid)) or db.get(Record, rid)):
        raise HTTPException(400, "bad_id")
    rec = Record(kind=kind, entity=KINDS[kind]["entity"], data=_clean(kind, body))
    if rid:
        rec.id = rid
    db.add(rec)
    db.flush()
    f = _apply_file(db, rec, body)
    db.commit()
    return serialize(rec, f)


@router.put("/records/{rid}")
def upsert_record(rid: str, body: dict = Body(...), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    if not ID_RE.match(rid):
        raise HTTPException(400, "bad_id")
    kind = body.get("kind")
    if kind not in KINDS:
        raise HTTPException(400, "unknown_kind")
    _gate(kind, s)
    rec = db.get(Record, rid)
    if rec and rec.kind != kind:
        raise HTTPException(400, "kind_mismatch")
    if not rec:
        rec = Record(id=rid, kind=kind, entity=KINDS[kind]["entity"])
        db.add(rec)
    keep = (rec.data or {}).get("dedup") if rec.data else None
    rec.data = _clean(kind, body)
    if keep:
        rec.data["dedup"] = keep  # 업로드로 들어온 거래는 수정해도 중복 검사 키 유지
    rec.updated_at = now()
    db.flush()
    f = _apply_file(db, rec, body)
    db.commit()
    return serialize(rec, f)


@router.delete("/records/{rid}")
def delete_record(rid: str, req: Request, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    rec = db.get(Record, rid)
    if not rec:
        raise HTTPException(404, "not_found")
    _gate(rec.kind, s)
    fid = rec.file_id
    db.delete(rec)
    db.commit()
    delete_file_if_orphan(db, fid)
    audit(db, s.user_id, "delete", f"{rec.kind}:{rid}", client_ip(req))
    return {"ok": True}


@router.get("/export")
def export_all(req: Request, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """전체 기록 JSON 백업 (파일 원본은 NAS 폴더 백업으로)."""
    audit(db, s.user_id, "export", "", client_ip(req))
    return {"version": 1, "exportedAt": now().isoformat(), "records": list_records("", s, db)}


@router.post("/import")
def import_records(payload: dict = Body(...), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """내보내기 JSON 또는 프로토타입 기록을 가져옵니다. 같은 id가 있으면 건너뜁니다. 파일은 따로 다시 올려야 합니다."""
    added, skipped = 0, 0
    for item in payload.get("records", [])[:20000]:
        kind = item.get("kind")
        rid = str(item.get("id") or "")
        if kind not in KINDS or kind in GATED or (rid and (not ID_RE.match(rid) or db.get(Record, rid))):
            skipped += 1
            continue
        rec = Record(kind=kind, entity=KINDS[kind]["entity"], data=_clean(kind, item))
        if rid:
            rec.id = rid
        db.add(rec)
        added += 1
    db.commit()
    return {"added": added, "skipped": skipped}


# ---------- 일괄 등록 (거래내역 업로드 등) ----------
def dedup_key(kind: str, d: dict, fields: list[str]) -> str:
    raw = kind + "|" + "|".join(str(d.get(f, "")).strip() for f in fields)
    return hashlib.sha1(raw.encode()).hexdigest()


@router.post("/records/bulk")
def bulk_create(payload: dict = Body(...), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """{"records": [...], "dedupBy": ["date","amount","memo","source"]}
    dedupBy를 주면 같은 값의 기록이 이미 있으면 건너뜁니다 (같은 명세서를 두 번 올려도 중복 안 됨)."""
    items = payload.get("records") or []
    fields = [str(f) for f in (payload.get("dedupBy") or [])][:8]
    if len(items) > 5000:
        raise HTTPException(413, "한 번에 5000건까지 올릴 수 있습니다.")
    seen: dict[str, set] = {}
    added = skipped = 0
    for item in items:
        kind = item.get("kind")
        if kind not in KINDS or kind in GATED:
            skipped += 1
            continue
        data = _clean(kind, item)
        if fields:
            if kind not in seen:
                seen[kind] = {r.data.get("dedup") for r in db.query(Record).filter(Record.kind == kind).all() if r.data}
            key = dedup_key(kind, data, fields)
            if key in seen[kind]:
                skipped += 1
                continue
            seen[kind].add(key)
            data["dedup"] = key
        rec = Record(kind=kind, entity=KINDS[kind]["entity"], data=data)
        fid = item.get("fileId")  # 자료 복사·이전 때 원본과 같은 파일을 가리킴 (파일은 하나만 보관)
        if fid and isinstance(fid, str) and db.get(StoredFile, fid):
            rec.file_id = fid
        db.add(rec)
        added += 1
    db.commit()
    return {"added": added, "skipped": skipped}


# ---------- 문서 자동 날인용 도장 ----------
OWNERS = {"brothers": "브라더스", "personal": "개인", "bj": "비엔제이", "irobo": "아이로보"}


def _stamp_record(db: DB, owner: str) -> Record | None:
    name = OWNERS.get(owner)
    if not name:
        raise HTTPException(404, "not_found")
    rows = [r for r in db.query(Record).filter(Record.kind == "seal").order_by(Record.updated_at.desc()).all()
            if (r.data or {}).get("owner") == name and (r.data or {}).get("useOnDocs") == "허용" and r.file_id]
    return rows[0] if rows else None


# 문서 작성 때 고를 수 있는 도장 (인감도장관리에서 '문서 자동 날인: 허용'으로 지정한 것만)
def _allowed_seals(db: DB) -> list[Record]:
    return [r for r in db.query(Record).filter(Record.kind == "seal").order_by(Record.updated_at.desc()).all()
            if (r.data or {}).get("useOnDocs") == "허용" and r.file_id]


@router.get("/stamp/list")
def stamp_list(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    return [{"id": r.id, "name": (r.data or {}).get("name", ""), "owner": (r.data or {}).get("owner", ""), "type": (r.data or {}).get("type", "")}
            for r in _allowed_seals(db)]


@router.get("/stamp/seal/{rid}")
def stamp_by_id(rid: str, req: Request, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    r = next((x for x in _allowed_seals(db) if x.id == rid), None)
    if not r:
        raise HTTPException(404, "no_stamp")
    f = db.get(StoredFile, r.file_id)
    if not f or not f.mime.startswith("image/"):
        raise HTTPException(404, "no_stamp")
    path = os.path.join(config.FILES_DIR, f.path)
    if not os.path.isfile(path):
        raise HTTPException(410, "file_missing")
    return FileResponse(path, media_type=f.mime, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.post("/stamp/use")
def stamp_use(req: Request, payload: dict = Body(...), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """문서를 저장·내려받을 때 어떤 도장을 어디에 썼는지 '인감 발급·사용 기록'에 남깁니다."""
    r = next((x for x in _allowed_seals(db) if x.id == str(payload.get("sealId") or "")), None)
    if not r:
        raise HTTPException(404, "no_stamp")
    d = r.data or {}
    doc = str(payload.get("doc") or "")[:120]
    db.add(Record(kind="seal_log", entity="personal", data={
        "date": now().astimezone().strftime("%Y-%m-%d"), "action": "문서 자동 날인", "owner": d.get("owner", ""),
        "purpose": doc or "문서", "submitTo": str(payload.get("to") or "")[:120], "memo": f"{d.get('name', '')} · JUWON OS 문서 작성"}))
    db.commit()
    audit(db, s.user_id, "stamp_use", f"{d.get('name', '')}:{doc}", client_ip(req))
    return {"ok": True}


@router.get("/stamp/{owner}/status")
def stamp_status(owner: str, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    r = _stamp_record(db, owner)
    return {"available": bool(r), "name": (r.data or {}).get("name", "") if r else ""}


@router.get("/stamp/{owner}")
def stamp_image(owner: str, req: Request, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """인감도장관리에서 '문서 날인 허용'으로 지정한 도장 이미지만 내줍니다 (견적서·발송확인서 날인용).
    도장 목록·다른 인감 파일은 여전히 비밀번호 재확인이 필요합니다."""
    r = _stamp_record(db, owner)
    if not r:
        raise HTTPException(404, "no_stamp")
    f = db.get(StoredFile, r.file_id)
    if not f or not f.mime.startswith("image/"):
        raise HTTPException(404, "no_stamp")
    path = os.path.join(config.FILES_DIR, f.path)
    if not os.path.isfile(path):
        raise HTTPException(410, "file_missing")
    audit(db, s.user_id, "stamp_use", f"{owner}:{f.name}", client_ip(req))
    return FileResponse(path, media_type=f.mime, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
