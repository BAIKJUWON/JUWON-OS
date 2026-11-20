"""GitHub REST API — 계정 활동·언어 통계, 저장소 README·커밋·파일 트리·이슈 조회 (읽기 전용).

토큰이 없으면 공개 저장소만, 시간당 60회까지 됩니다. .env에 GITHUB_TOKEN(읽기 권한 fine-grained 토큰)을 넣으면 5,000회.
응답은 30분 동안 DB에 캐시합니다.
"""
import json
import re
import time
import urllib.parse
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DB

from . import config
from .db import get_db
from .kvstore import HttpError, http, kv_get, kv_set
from .models import Session
from .security import require_user

router = APIRouter(prefix="/api/github", tags=["github"])
API = "https://api.github.com"
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
TTL = 1800


def _h(raw: bool = False) -> dict:
    h = {"Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json", "User-Agent": "juwon-os",
         "X-GitHub-Api-Version": "2022-11-28"}
    if config.GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"
    return h


def _get(path: str, raw: bool = False, ok404: bool = False):
    try:
        _, _, text = http("GET", API + path, _h(raw), timeout=20)
    except HttpError as e:
        if ok404 and e.status in (404, 409):
            return None
        if e.status == 403 and "rate limit" in e.body.lower():
            raise HTTPException(429, "GitHub 조회 한도(시간당 60회)를 넘었습니다. 잠시 뒤에 하거나 .env에 GITHUB_TOKEN을 넣으세요.")
        if e.status == 404:
            raise HTTPException(404, "GitHub에서 찾을 수 없습니다 (이름 확인, 비공개 저장소는 GITHUB_TOKEN 필요).")
        raise HTTPException(502, f"GitHub 요청 실패 ({e.status or '연결 안 됨'}): {e.body[:150]}")
    return text if raw else json.loads(text)


def _cached(db: DB, key: str, fn, fresh: bool):
    c = kv_get(db, key) or {}
    if not fresh and c.get("at", 0) > time.time() - TTL:
        return c["v"]
    v = fn()
    kv_set(db, key, {"at": time.time(), "v": v})
    return v


def _chk(*names: str) -> None:
    for n in names:
        if not NAME.match(n or ""):
            raise HTTPException(400, "GitHub 이름이 올바르지 않습니다.")


@router.get("/user/{user}")
def user_summary(user: str, fresh: bool = False, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    _chk(user)

    def load():
        prof = _get(f"/users/{user}")
        repos = _get(f"/users/{user}/repos?per_page=100&sort=pushed") or []
        langs: Counter = Counter()
        for r in repos[:25]:
            if r.get("fork"):
                continue
            for k, v in (_get(f"/repos/{user}/{r['name']}/languages", ok404=True) or {}).items():
                langs[k] += v
        events = _get(f"/users/{user}/events/public?per_page=100", ok404=True) or []
        since = datetime.now(timezone.utc) - timedelta(days=84)
        weeks: Counter = Counter()
        kinds: Counter = Counter()
        for e in events:
            t = datetime.fromisoformat(e["created_at"].replace("Z", "+00:00"))
            if t < since:
                continue
            kinds[e["type"]] += 1
            if e["type"] == "PushEvent":
                wk = (t - timedelta(days=t.weekday())).strftime("%Y-%m-%d")
                weeks[wk] += int((e.get("payload") or {}).get("size") or (e.get("payload") or {}).get("distinct_size") or 1)
        return {
            "user": user, "name": prof.get("name") or user, "bio": prof.get("bio"), "avatar": prof.get("avatar_url"),
            "followers": prof.get("followers"), "publicRepos": prof.get("public_repos"),
            "repos": [{"name": r["name"], "desc": r.get("description"), "lang": r.get("language"), "stars": r.get("stargazers_count", 0),
                       "forks": r.get("forks_count", 0), "pushed": r.get("pushed_at"), "fork": r.get("fork"), "topics": r.get("topics") or [],
                       "private": r.get("private"), "url": r.get("html_url")} for r in repos],
            "languages": dict(langs.most_common(12)), "weeks": dict(sorted(weeks.items())), "events": dict(kinds),
            "tokenUsed": bool(config.GITHUB_TOKEN),
        }
    return _cached(db, f"gh_user:{user}", load, fresh)


@router.get("/repo/{user}/{repo}")
def repo_detail(user: str, repo: str, fresh: bool = False, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    _chk(user, repo)

    def load():
        info = _get(f"/repos/{user}/{repo}")
        branch = info.get("default_branch") or "main"
        readme = _get(f"/repos/{user}/{repo}/readme", raw=True, ok404=True) or ""
        commits = _get(f"/repos/{user}/{repo}/commits?per_page=30", ok404=True) or []
        tree = _get(f"/repos/{user}/{repo}/git/trees/{urllib.parse.quote(branch)}?recursive=1", ok404=True) or {}
        issues = _get(f"/repos/{user}/{repo}/issues?state=all&per_page=30", ok404=True) or []
        return {
            "name": info["name"], "desc": info.get("description"), "branch": branch, "url": info.get("html_url"),
            "stars": info.get("stargazers_count", 0), "forks": info.get("forks_count", 0), "pushed": info.get("pushed_at"),
            "languages": _get(f"/repos/{user}/{repo}/languages", ok404=True) or {}, "readme": readme[:60000],
            "commits": [{"sha": c["sha"][:7], "msg": (c.get("commit") or {}).get("message", "").split("\n")[0][:200],
                         "date": ((c.get("commit") or {}).get("author") or {}).get("date"), "author": ((c.get("commit") or {}).get("author") or {}).get("name"),
                         "url": c.get("html_url")} for c in commits],
            "tree": [{"path": t["path"], "type": t["type"], "size": t.get("size")} for t in (tree.get("tree") or [])[:800]],
            "truncated": bool(tree.get("truncated")),
            "issues": [{"no": i["number"], "title": i["title"], "state": i["state"], "pr": "pull_request" in i, "date": i.get("created_at"),
                        "labels": [l["name"] for l in i.get("labels") or []], "url": i.get("html_url")} for i in issues],
        }
    return _cached(db, f"gh_repo:{user}/{repo}", load, fresh)


@router.get("/file/{user}/{repo}")
def repo_file(user: str, repo: str, path: str, ref: str = "", s: Session = Depends(require_user), db: DB = Depends(get_db)):
    _chk(user, repo)
    if ".." in path or len(path) > 400 or len(ref) > 100:
        raise HTTPException(400, "경로가 올바르지 않습니다.")
    q = f"?ref={urllib.parse.quote(ref)}" if ref else ""
    text = _get(f"/repos/{user}/{repo}/contents/{urllib.parse.quote(path)}{q}", raw=True)
    return {"path": path, "text": text[:200000], "truncated": len(text) > 200000}
