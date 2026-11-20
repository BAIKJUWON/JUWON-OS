"""파일 업로드·열람. 원본은 FILES_DIR(NAS 폴더)에 저장하고 DB에는 메타데이터만 둡니다."""
import hashlib
import mimetypes
import os
import shutil
import subprocess
import re
import urllib.parse
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session as DB

from . import config
from .db import get_db
from .models import Record, Session, StoredFile, new_id
from .security import audit, client_ip, recent_reauth, require_user

router = APIRouter(prefix="/api/files", tags=["files"])

TEXT_EXT = re.compile(r"\.(c|h|cpp|hpp|cc|ino|py|js|mjs|ts|tsx|jsx|java|kt|go|rs|cs|php|rb|swift|html?|css|scss|json|md|txt"
                      r"|csv|ya?ml|toml|ini|cfg|conf|sh|bat|ps1|xml|sql|gradle|cmake|mk|log)$", re.I)
TEXT_NAMES = {"makefile", "dockerfile", "readme", "license"}
# 서버에서 브라우저가 바로 그려도 안전한 형식만 inline, 나머지는 첨부(다운로드)로 보냄
INLINE_SAFE = {"application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}
CHUNK = 1024 * 1024


def _is_text(name: str, ctype: str) -> bool:
    return bool(TEXT_EXT.search(name)) or name.lower() in TEXT_NAMES or ctype.startswith("text/")


def _safe_name(name: str) -> str:
    name = os.path.basename(name or "file").replace("\x00", "")
    return name[:200] or "file"


def file_meta(f: StoredFile | None) -> dict:
    if not f:
        return {}
    return {"fileId": f.id, "fileName": f.name, "fileSize": f.size, "fileType": f.mime, "isText": f.is_text,
            "fileUrl": f"/api/files/{f.id}", "vault": f.vault}


def delete_file_if_orphan(db: DB, file_id: str | None) -> None:
    if not file_id:
        return
    if db.query(Record).filter(Record.file_id == file_id).count():
        return
    f = db.get(StoredFile, file_id)
    if not f:
        return
    p = os.path.join(config.FILES_DIR, f.path)
    db.delete(f)
    db.commit()
    try:
        os.remove(p)
    except FileNotFoundError:
        pass


@router.post("")
async def upload(files: list[UploadFile], req: Request, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    out = []
    limit = config.MAX_UPLOAD_MB * 1024 * 1024
    for up in files:
        name = _safe_name(up.filename or "file")
        ctype = (up.content_type or "").split(";")[0].strip().lower() or (mimetypes.guess_type(name)[0] or "application/octet-stream")
        is_text = _is_text(name, ctype)
        if is_text:
            ctype = "text/plain"
        fid = new_id()
        rel = os.path.join(datetime.now().strftime("%Y/%m"), fid)
        dest = os.path.join(config.FILES_DIR, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        h, size = hashlib.sha256(), 0
        try:
            with open(dest, "wb") as fp:
                while chunk := await up.read(CHUNK):
                    size += len(chunk)
                    if size > limit:
                        raise HTTPException(413, f"파일이 {config.MAX_UPLOAD_MB}MB를 넘습니다: {name}")
                    h.update(chunk)
                    fp.write(chunk)
        except HTTPException:
            os.remove(dest)
            raise
        sha = h.hexdigest()
        same = db.query(StoredFile).filter(StoredFile.sha256 == sha).first()
        f = StoredFile(id=fid, sha256=sha, path=rel, name=name, mime=ctype[:127], size=size, is_text=is_text)
        db.add(f)
        db.commit()
        meta = file_meta(f)
        if same:  # 같은 내용의 파일이 이미 있음 — 저장은 하되 화면에서 알려 줌
            meta.update(duplicate=True, dupName=same.name)
        out.append(meta)
    audit(db, s.user_id, "upload", f"{len(out)} files", client_ip(req))
    return out


@router.get("/{file_id}")
def download(file_id: str, req: Request, dl: int = 0, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    f = db.get(StoredFile, file_id)
    if not f:
        raise HTTPException(404, "not_found")
    if f.vault:
        if not recent_reauth(s):
            raise HTTPException(403, "reauth_required")
        audit(db, s.user_id, "vault_view", f.name, client_ip(req))
    path = os.path.join(config.FILES_DIR, f.path)
    if not os.path.isfile(path):
        raise HTTPException(410, "file_missing")
    inline = (f.mime in INLINE_SAFE or f.is_text) and not dl
    disp = "inline" if inline else "attachment"
    headers = {
        "Content-Disposition": f"{disp}; filename*=UTF-8''{urllib.parse.quote(f.name)}",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "private, max-age=0, no-store" if f.vault else "private, max-age=3600",
    }
    if f.mime != "application/pdf":
        headers["Content-Security-Policy"] = "sandbox; default-src 'none'; img-src 'self'"
    media = "text/plain; charset=utf-8" if f.is_text else f.mime
    return FileResponse(path, media_type=media, headers=headers)


THUMB_OK = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}


@router.get("/{file_id}/thumb")
def thumb(file_id: str, w: int = 400, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """이미지 썸네일(JPEG). 원본은 그대로 두고 thumbs 폴더에 한 번 만들어 재사용."""
    f = db.get(StoredFile, file_id)
    if not f:
        raise HTTPException(404, "not_found")
    if f.vault and not recent_reauth(s):
        raise HTTPException(403, "reauth_required")
    w = 200 if w <= 200 else 400 if w <= 400 else 800
    src = os.path.join(config.FILES_DIR, f.path)
    is_pdf = f.mime == "application/pdf"
    if (f.mime not in THUMB_OK and not is_pdf) or not os.path.isfile(src):
        raise HTTPException(415, "썸네일을 만들 수 없는 형식입니다.")
    dst = os.path.join(config.FILES_DIR, "thumbs", f"{f.id}_{w}.jpg")
    if is_pdf:  # PDF는 첫 페이지를 그림으로 (poppler pdftoppm 필요)
        if not os.path.isfile(dst):
            if not shutil.which("pdftoppm"):
                raise HTTPException(415, "PDF 썸네일 도구(pdftoppm)가 없습니다.")
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                subprocess.run(["pdftoppm", "-jpeg", "-jpegopt", "quality=80", "-f", "1", "-l", "1", "-scale-to", str(w),
                                "-singlefile", src, dst[:-4]], timeout=30, check=True, capture_output=True)
            except Exception:
                raise HTTPException(415, "PDF 첫 페이지를 그리지 못했습니다.")
        return FileResponse(dst, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=86400"})
    if not os.path.isfile(dst):
        try:
            from PIL import Image, ImageOps
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with Image.open(src) as im:
                im = ImageOps.exif_transpose(im)
                im.thumbnail((w, w * 2))
                im.convert("RGB").save(dst, "JPEG", quality=82)
        except Exception:
            return FileResponse(src, media_type=f.mime, headers={"Cache-Control": "private, max-age=3600"})
    return FileResponse(dst, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=86400"})
