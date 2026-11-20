"""묶음 가져오기 — manifest.json + 파일이 든 zip을 한 번에 기록·파일로 등록 (비엔제이 서류 정리본 등).

manifest.json: {"records": [{"id": "...", "kind": "...", ...필드..., "_file": "files/이름.pdf"}]}
- 같은 id가 있으면 내용·파일을 새것으로 바꿈 (여러 번 올려도 중복으로 쌓이지 않음)
- 같은 내용(sha256)의 파일이 이미 서버에 있으면 그 파일을 재사용
"""
import hashlib
import json
import mimetypes
import os
import zipfile
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session as DB

from . import config
from .db import get_db
from .files import _is_text, _safe_name
from .kinds import GATED, KINDS
from .models import Record, Session, StoredFile, new_id, now
from .records import ID_RE, _clean
from .security import audit, client_ip, require_user

router = APIRouter(prefix="/api/import", tags=["bundle"])
MAX_BUNDLE = 500 * 1024 * 1024


@router.post("/bundle")
async def import_bundle(file: UploadFile, req: Request, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    tmp = os.path.join(config.FILES_DIR, f".bundle_{new_id()}.zip")
    size = 0
    with open(tmp, "wb") as fp:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_BUNDLE:
                fp.close()
                os.remove(tmp)
                raise HTTPException(413, "묶음 파일이 500MB를 넘습니다.")
            fp.write(chunk)
    added = updated = files = reused = 0
    skipped: list[str] = []
    try:
        with zipfile.ZipFile(tmp) as z:
            try:
                manifest = json.loads(z.read("manifest.json").decode("utf-8"))
            except KeyError:
                raise HTTPException(400, "zip 안에 manifest.json이 없습니다.")
            # 윈도우·리눅스 zip 도구가 한글 파일명을 UTF-8 표시 없이 넣은 경우도 찾을 수 있게
            for info in z.infolist():
                if not info.flag_bits & 0x800:
                    try:
                        fixed = info.filename.encode("cp437").decode("utf-8")
                    except (UnicodeEncodeError, UnicodeDecodeError):
                        try:
                            fixed = info.filename.encode("cp437").decode("cp949")
                        except (UnicodeEncodeError, UnicodeDecodeError):
                            continue
                    z.NameToInfo[fixed] = info
            names = set(z.NameToInfo)
            for item in manifest.get("records", [])[:5000]:
                kind, rid = item.get("kind"), str(item.get("id") or "")
                if kind not in KINDS or kind in GATED or (rid and not ID_RE.match(rid)):
                    skipped.append(f"{kind}:{rid}")
                    continue
                fid = None
                fpath = item.get("_file")
                if fpath:
                    if fpath not in names or ".." in fpath:
                        skipped.append(f"파일 없음 {fpath}")
                        continue
                    raw = z.read(fpath)
                    if len(raw) > config.MAX_UPLOAD_MB * 1024 * 1024 * 20:
                        skipped.append(f"너무 큼 {fpath}")
                        continue
                    sha = hashlib.sha256(raw).hexdigest()
                    same = db.query(StoredFile).filter(StoredFile.sha256 == sha).first()
                    if same:
                        fid = same.id
                        reused += 1
                    else:
                        name = _safe_name(item.get("_name") or fpath)
                        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
                        is_text = _is_text(name, mime)
                        fid = new_id()
                        rel = os.path.join(datetime.now().strftime("%Y/%m"), fid)
                        dest = os.path.join(config.FILES_DIR, rel)
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        with open(dest, "wb") as out:
                            out.write(raw)
                        db.add(StoredFile(id=fid, sha256=sha, path=rel, name=name, mime=("text/plain" if is_text else mime)[:127], size=len(raw), is_text=is_text))
                        db.flush()
                        files += 1
                data = _clean(kind, {k: v for k, v in item.items() if not k.startswith("_")})
                rec = db.get(Record, rid) if rid else None
                if rec and rec.kind != kind:
                    skipped.append(f"id 충돌 {rid}")
                    continue
                if rec:
                    rec.data = data
                    rec.updated_at = now()
                    updated += 1
                else:
                    rec = Record(kind=kind, entity=KINDS[kind]["entity"], data=data)
                    if rid:
                        rec.id = rid
                    db.add(rec)
                    added += 1
                if fid:
                    rec.file_id = fid
                    f = db.get(StoredFile, fid)
                    rule = KINDS[kind].get("vault")
                    f.vault = bool(f.vault or (rule and rule(data)))
                db.flush()
            db.commit()
    except zipfile.BadZipFile:
        raise HTTPException(400, "zip 파일이 아닙니다.")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    audit(db, s.user_id, "import_bundle", f"+{added} ~{updated} files {files}", client_ip(req))
    return {"added": added, "updated": updated, "files": files, "reusedFiles": reused, "skipped": skipped[:30]}
