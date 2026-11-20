"""은행·카드 거래내역 파일(CSV·XLSX) 읽기 — 인증서 없이 무료로 쓰는 방법.

은행마다 양식이 달라서 머리글 이름으로 열을 찾습니다. 결과는 미리보기용으로만 돌려주고,
저장은 화면에서 확인한 뒤 /api/records/bulk 로 합니다 (같은 거래는 자동으로 건너뜀).
"""
import csv
import io
import re
from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException, UploadFile

from .models import Session
from .security import require_user

router = APIRouter(prefix="/api/finance", tags=["finance"])

COLS = {
    "date": ["거래일시", "거래일자", "거래일", "거래날짜", "이용일시", "이용일자", "이용일", "승인일시", "승인일자", "승인일", "일자", "날짜", "일시"],
    "time": ["거래시간", "이용시간", "승인시간", "시간"],
    "out": ["출금금액", "출금액", "찾으신금액", "출금", "지급금액", "지급액", "인출금액"],
    "in": ["입금금액", "입금액", "맡기신금액", "입금", "예입금액"],
    "amount": ["이용금액", "승인금액", "결제금액", "거래금액", "금액", "결제예정금액"],
    "memo": ["가맹점명", "이용가맹점", "가맹점", "거래내용", "기재내용", "내용", "적요", "받는분", "보낸분", "거래처", "메모", "통장표시내용"],
    "balance": ["거래후잔액", "거래후 잔액", "잔액"],
    "cancel": ["취소여부", "승인취소", "취소", "상태"],
}
MAX_BYTES = 10 * 1024 * 1024


def _norm(s) -> str:
    return re.sub(r"\s+", "", str(s or "")).replace("(원)", "")


def _find_header(rows: list[list]) -> tuple[int, dict]:
    best = (-1, {})
    for i, row in enumerate(rows[:40]):
        cells = [_norm(c) for c in row]
        found = {}
        for key, names in COLS.items():
            for n in names:
                nn = _norm(n)
                for j, c in enumerate(cells):
                    if c and (c == nn or (len(nn) >= 2 and c.startswith(nn))) and j not in found.values():
                        found.setdefault(key, j)
                        break
                if key in found:
                    break
        ok = "date" in found and ("amount" in found or "out" in found or "in" in found)
        if ok and len(found) > len(best[1]):
            best = (i, found)
    return best


def parse_amount(v) -> int | None:
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return int(round(v))
    s = str(v).strip().replace(",", "").replace("원", "").replace(" ", "")
    neg = s.startswith("-") or (s.startswith("(") and s.endswith(")"))
    s = re.sub(r"[^\d.]", "", s)
    if not s:
        return None
    n = int(round(float(s)))
    return -n if neg else n


def parse_date(v) -> str:
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d")
    if isinstance(v, date):
        return v.strftime("%Y-%m-%d")
    s = str(v or "").strip()
    m = re.search(r"(20\d{2})[.\-/년\s]*(\d{1,2})[.\-/월\s]*(\d{1,2})", s)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if 1 <= mo <= 12 and 1 <= d <= 31:
            return f"{y:04d}-{mo:02d}-{d:02d}"
    m = re.fullmatch(r"(20\d{2})(\d{2})(\d{2})\d*", re.sub(r"\D", "", s))
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    m = re.fullmatch(r"(\d{2})[.\-/](\d{1,2})[.\-/](\d{1,2})", s[:8])  # 26.11.12
    if m:
        return f"20{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    return ""


def read_rows(name: str, raw: bytes) -> list[list]:
    low = name.lower()
    if low.endswith(".xls") and not low.endswith(".xlsx"):
        if raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            raise HTTPException(400, "엑셀 97-2003(.xls) 파일은 읽을 수 없습니다. 엑셀에서 '다른 이름으로 저장' → .xlsx 또는 .csv로 바꿔 올려 주세요.")
        # 일부 은행은 .xls 이름으로 HTML 표를 내려줌
        text = raw.decode("utf-8", "ignore") if b"charset=utf-8" in raw[:2000].lower() else raw.decode("cp949", "ignore")
        return _html_rows(text)
    if low.endswith(".xlsx") or raw[:2] == b"PK":
        from openpyxl import load_workbook
        wb = load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
        ws = wb.worksheets[0]
        return [[c for c in row] for row in ws.iter_rows(values_only=True)]
    for enc in ("utf-8-sig", "cp949", "euc-kr"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise HTTPException(400, "파일 글자 인코딩을 알 수 없습니다.")
    if "<table" in text[:5000].lower():
        return _html_rows(text)
    dialect = csv.excel_tab if text.count("\t") > text.count(",") else csv.excel
    return [row for row in csv.reader(io.StringIO(text), dialect)]


def _html_rows(text: str) -> list[list]:
    rows = []
    for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", text, re.S | re.I):
        cells = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", tr, re.S | re.I)
        rows.append([re.sub(r"<[^>]+>|&nbsp;", " ", c).strip() for c in cells])
    return rows


def parse_statement(name: str, raw: bytes) -> dict:
    rows = read_rows(name, raw)
    hi, cols = _find_header(rows)
    if hi < 0:
        raise HTTPException(400, "거래일·금액 열을 찾지 못했습니다. 은행·카드 앱에서 '거래내역 엑셀(xlsx/csv) 저장'으로 받은 파일인지 확인하세요.")
    head = rows[hi]
    out, skipped = [], 0
    for row in rows[hi + 1:]:
        get = lambda k: row[cols[k]] if k in cols and cols[k] < len(row) else None  # noqa: E731
        d = parse_date(get("date"))
        if not d:
            skipped += 1
            continue
        if "cancel" in cols and re.search(r"취소|cancel", str(get("cancel") or ""), re.I):
            skipped += 1
            continue
        outv, inv = parse_amount(get("out")), parse_amount(get("in"))
        if outv or inv:
            if outv and outv > 0:
                direction, amt = "지출", outv
            else:
                direction, amt = "수입", inv or 0
        else:
            a = parse_amount(get("amount"))
            if not a:
                skipped += 1
                continue
            direction, amt = ("수입", -a) if a < 0 else ("지출", a)
        if not amt:
            skipped += 1
            continue
        out.append({"date": d, "dir": direction, "amount": amt, "memo": str(get("memo") or "").strip()[:120],
                    "balance": parse_amount(get("balance"))})
    return {"columns": {k: str(head[v]) for k, v in cols.items() if v < len(head)}, "rows": out, "skipped": skipped,
            "kind": "bank" if ("out" in cols or "in" in cols) else "card"}


@router.post("/parse-statement")
async def parse(file: UploadFile, s: Session = Depends(require_user)):
    raw = await file.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, "파일이 10MB를 넘습니다.")
    return parse_statement(file.filename or "file", raw)
