"""암호화된 서버 내부 값 저장 (토큰·연결번호). DB kv 테이블 사용."""
import json
import urllib.error
import urllib.request

from sqlalchemy.orm import Session as DB

from .models import KV, now
from .security import dec, enc


def kv_get(db: DB, key: str, default=None):
    row = db.get(KV, key)
    if not row:
        return default
    try:
        return json.loads(dec(row.value) or "null")
    except ValueError:
        return default


def kv_set(db: DB, key: str, value) -> None:
    row = db.get(KV, key)
    data = enc(json.dumps(value, ensure_ascii=False))
    if row:
        row.value = data
        row.updated_at = now()
    else:
        db.add(KV(key=key, value=data))
    db.commit()


def kv_del(db: DB, key: str) -> None:
    row = db.get(KV, key)
    if row:
        db.delete(row)
        db.commit()


class HttpError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body


def http(method: str, url: str, headers: dict, body: bytes | None = None, timeout: int = 20) -> tuple[int, dict, str]:
    """표준 라이브러리만 쓰는 간단한 HTTP 요청. (상태코드, 응답헤더, 본문 문자열)"""
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raise HttpError(e.code, e.read().decode("utf-8", "replace")) from None
    except (urllib.error.URLError, TimeoutError) as e:
        raise HttpError(0, str(e)) from None
