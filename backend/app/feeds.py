"""Hearts2Hearts 소식 자동 수집 — 공개 RSS만 사용 (로그인·보안 우회 없음).

- 뉴스: Google 뉴스 RSS 검색
- 유튜브: 채널 공개 RSS (https://www.youtube.com/feeds/videos.xml?channel_id=...)
  채널 ID를 .env H2H_YOUTUBE_CHANNEL_ID에 넣거나, 비우면 @핸들 페이지에서 한 번 찾아 저장
- SM·SMTOWN 공지, 위버스: 공개 RSS가 없어 자동 수집하지 않음 (화면에서 바로가기 + 직접 등록)
결과는 kv에 저장하고, 마지막 갱신 시각과 출처별 오류를 함께 남깁니다.
"""
import os
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DB

from .db import get_db
from .kvstore import HttpError, http, kv_get, kv_set
from .models import Session
from .security import require_user

router = APIRouter(prefix="/api/feeds", tags=["feeds"])
UA = {"User-Agent": "Mozilla/5.0 (JUWON OS personal reader)", "Accept-Language": "ko-KR,ko;q=0.9"}
NEWS_Q = os.getenv("H2H_NEWS_QUERY", "")
YT_HANDLE = os.getenv("H2H_YOUTUBE_HANDLE", "")
YT_ID = os.getenv("H2H_YOUTUBE_CHANNEL_ID", "").strip()
REFRESH_MIN = int(os.getenv("H2H_REFRESH_MINUTES", "0"))


def _iso(s: str) -> str:
    try:
        return parsedate_to_datetime(s).isoformat()
    except (TypeError, ValueError):
        return s or ""


def _news() -> list[dict]:
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode({"q": NEWS_Q, "hl": "ko", "gl": "KR", "ceid": "KR:ko"})
    _, _, text = http("GET", url, UA, timeout=20)
    out = []
    for it in ET.fromstring(text).iter("item"):
        src = it.find("source")
        out.append({"src": "뉴스", "title": (it.findtext("title") or "").strip(), "link": it.findtext("link") or "",
                    "date": _iso(it.findtext("pubDate") or ""), "by": src.text if src is not None else ""})
    return out[:60]


def _channel_id(db: DB) -> str:
    if YT_ID:
        return YT_ID
    saved = (kv_get(db, "h2h_ytid") or {}).get("id")
    if saved:
        return saved
    _, _, html = http("GET", f"https://www.youtube.com/{urllib.parse.quote(YT_HANDLE)}", UA, timeout=20)
    m = re.search(r'"(?:channelId|externalId)":"(UC[\w-]{22})"', html) or re.search(r'channel/(UC[\w-]{22})', html)
    if not m:
        raise ValueError(f"{YT_HANDLE} 채널 ID를 찾지 못했습니다. .env에 H2H_YOUTUBE_CHANNEL_ID를 넣어 주세요.")
    kv_set(db, "h2h_ytid", {"id": m.group(1), "handle": YT_HANDLE})
    return m.group(1)


def _youtube(db: DB) -> list[dict]:
    cid = _channel_id(db)
    _, _, text = http("GET", f"https://www.youtube.com/feeds/videos.xml?channel_id={cid}", UA, timeout=20)
    ns = {"a": "http://www.w3.org/2005/Atom", "yt": "http://www.youtube.com/xml/schemas/2015", "m": "http://search.yahoo.com/mrss/"}
    out = []
    for e in ET.fromstring(text).findall("a:entry", ns):
        vid = e.findtext("yt:videoId", "", ns)
        title = e.findtext("a:title", "", ns)
        t = title.lower()
        cat = "뮤직비디오" if " mv" in f" {t}" or "m/v" in t else "안무" if any(k in t for k in ("dance practice", "안무", "choreograph", "performance")) else "비하인드" if any(k in t for k in ("behind", "비하인드", "making")) else "자체 콘텐츠"
        out.append({"src": "유튜브", "title": title, "link": f"https://www.youtube.com/watch?v={vid}", "vid": vid, "cat": cat,
                    "date": e.findtext("a:published", "", ns), "thumb": f"https://i.ytimg.com/vi/{vid}/hqdefault.jpg"})
    return out


def refresh(db: DB) -> dict:
    old = kv_get(db, "h2h_feed") or {"items": [], "errors": {}}
    seen = {i["link"]: i for i in old.get("items", [])}
    errors: dict = {}
    for name, fn in (("뉴스", _news), ("유튜브", lambda: _youtube(db))):
        try:
            for i in fn():
                if i["link"] and i["link"] not in seen:
                    i["found"] = time.time()
                    seen[i["link"]] = i
        except (HttpError, ET.ParseError, ValueError) as e:
            errors[name] = f"{type(e).__name__}: {getattr(e, 'body', '') or e}"[:200]
    # 같은 제목(언론사만 다른 중복 기사)은 하나만
    items, titles = [], set()
    for i in sorted(seen.values(), key=lambda x: x.get("date", ""), reverse=True):
        key = (i["src"], re.sub(r"\W+", "", i["title"].split(" - ")[0])[:40])
        if key in titles:
            continue
        titles.add(key)
        items.append(i)
    data = {"items": items[:300], "errors": errors, "at": time.time()}
    kv_set(db, "h2h_feed", data)
    return data


def maybe_refresh(db: DB) -> None:
    d = kv_get(db, "h2h_feed") or {}
    if time.time() - float(d.get("at", 0)) >= REFRESH_MIN * 60:
        refresh(db)


@router.get("/h2h")
def get_feed(fresh: bool = False, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    d = refresh(db) if fresh or not kv_get(db, "h2h_feed") else kv_get(db, "h2h_feed")
    last_seen = float((kv_get(db, "h2h_seen") or {}).get("at", 0))
    return {**d, "lastSeen": last_seen, "ytId": YT_ID or (kv_get(db, "h2h_ytid") or {}).get("id", "")}


@router.post("/h2h/seen")
def mark_seen(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    kv_set(db, "h2h_seen", {"at": time.time()})
    return {"ok": True}
