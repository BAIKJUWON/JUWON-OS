"""사업 ERP 보조 API.

- /api/erp/parse-table : 쇼핑몰 주문·카드매출·현금영수증 같은 엑셀(xlsx)·CSV 파일을 표(머리글+행)로 읽어 돌려줍니다.
  어떤 열이 무엇인지는 화면에서 고르고, 저장은 /api/records/bulk (중복 자동 건너뜀)로 합니다.
- /api/erp/zip : 여러 파일(상세페이지 이미지 등)을 zip 하나로 내려받습니다.
외부 쇼핑몰·은행 API는 쓰지 않습니다 (파일 가져오기 방식).
"""
import io
import os
import re
import zipfile
from datetime import date, datetime

from fastapi import APIRouter, Body, Depends, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session as DB

from . import config
from .db import get_db
from .models import Session, StoredFile
from .security import audit, client_ip, require_user
from .statement import read_rows

router = APIRouter(prefix="/api/erp", tags=["erp"])
MAX_BYTES = 15 * 1024 * 1024
MAX_ROWS = 5000


def _cell(v):
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M") if (v.hour or v.minute) else v.strftime("%Y-%m-%d")
    if isinstance(v, date):
        return v.strftime("%Y-%m-%d")
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v).strip()


def parse_table(name: str, raw: bytes) -> dict:
    rows = [[_cell(c) for c in r] for r in read_rows(name, raw)]
    rows = [r for r in rows if any(c for c in r)]
    if not rows:
        raise HTTPException(400, "표에서 읽을 내용이 없습니다.")
    # 머리글 = 앞쪽 20줄 중 '글자 칸'이 가장 많은 줄 (숫자만 있는 칸은 머리글이 아님)
    def score(r):
        return sum(1 for c in r if c and not re.fullmatch(r"[-\d,.\s:/]+", c))
    hi = max(range(min(20, len(rows))), key=lambda i: (score(rows[i]), -i))
    head = [h or f"열{i + 1}" for i, h in enumerate(rows[hi])]
    body = []
    for r in rows[hi + 1:hi + 1 + MAX_ROWS]:
        r = (r + [""] * len(head))[:len(head)]
        if any(r):
            body.append(r)
    return {"headers": head, "rows": body, "total": len(rows) - hi - 1, "cut": len(rows) - hi - 1 > MAX_ROWS}


@router.post("/parse-table")
async def parse(file: UploadFile, s: Session = Depends(require_user)):
    raw = await file.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, "파일이 15MB를 넘습니다.")
    if raw[:4] == b"\xd0\xcf\x11\xe0" and (file.filename or "").lower().endswith(".xlsx"):
        raise HTTPException(400, "암호가 걸린 엑셀 파일입니다. 엑셀에서 열어 암호를 풀고 다시 저장하거나 CSV로 저장해 올려 주세요.")
    return parse_table(file.filename or "file", raw)


SAFE = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


@router.post("/zip")
def zip_files(req: Request, payload: dict = Body(...), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """{"name": "상세페이지.zip", "files": [{"id": 파일ID, "name": "01_메인.png"}]} — 고보안(vault) 파일은 넣지 않습니다."""
    items = payload.get("files") or []
    if not isinstance(items, list) or not items or len(items) > 200:
        raise HTTPException(400, "파일을 1~200개 골라 주세요.")
    buf = io.BytesIO()
    used: set[str] = set()
    n = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for it in items:
            f = db.get(StoredFile, str((it or {}).get("id") or ""))
            if not f or f.vault:
                continue
            path = os.path.join(config.FILES_DIR, f.path)
            if not os.path.isfile(path):
                continue
            nm = SAFE.sub("_", str(it.get("name") or f.name))[:150] or f.name
            base, k = nm, 2
            while nm in used:
                stem, dot, ext = base.rpartition(".")
                nm = f"{stem}_{k}.{ext}" if dot else f"{base}_{k}"
                k += 1
            used.add(nm)
            z.write(path, nm)
            n += 1
    if not n:
        raise HTTPException(404, "내려받을 수 있는 파일이 없습니다.")
    audit(db, s.user_id, "zip_download", f"{n} files", client_ip(req))
    name = SAFE.sub("_", str(payload.get("name") or "files.zip"))[:100]
    from urllib.parse import quote
    return StreamingResponse(io.BytesIO(buf.getvalue()), media_type="application/zip",
                             headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}"})
