"""GitHub 웹사이트 CMS — GitHub Pages 저장소(정적 사이트·Jekyll)에 글·이미지를 커밋으로 반영합니다.

연결 방법 (둘 중 하나):
  1) OAuth 앱: .env 에 GITHUB_OAUTH_ID / GITHUB_OAUTH_SECRET / PUBLIC_URL 을 넣으면 화면의 'GitHub로 연결' 버튼이 생깁니다.
  2) 토큰 붙여넣기: GitHub → Settings → Developer settings → Fine-grained token
     (대상 저장소만, Contents: Read and write / Pull requests: Read and write / Actions·Pages: Read).
토큰은 DB kv 테이블에 암호화(FIELD_KEY)해 저장하고 화면으로는 절대 돌려주지 않습니다.
저장소 계정(PROJECT_OWNER, PORTFOLIO_OWNER)마다 그 계정의 토큰을 따로 연결합니다.
"""
import base64
import json
import os
import re
import secrets
import time
import urllib.parse

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as DB

from . import config
from .db import get_db
from .kvstore import HttpError, http, kv_del, kv_get, kv_set
from .models import Session, StoredFile
from .security import audit, client_ip, recent_reauth, require_user

router = APIRouter(prefix="/api/cms", tags=["cms"])
API = "https://api.github.com"
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
TOK_KEY = "gh_tokens"
MAX_COMMIT_BYTES = 40 * 1024 * 1024


def _tokens(db: DB) -> dict:
    return kv_get(db, TOK_KEY) or {}


def _h(token: str = "", raw: bool = False) -> dict:
    h = {"Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json", "User-Agent": "juwon-os-cms",
         "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _call(method: str, path: str, token: str = "", payload=None, raw: bool = False, ok404: bool = False):
    body = json.dumps(payload).encode() if payload is not None else None
    hd = _h(token, raw)
    if body is not None:
        hd["Content-Type"] = "application/json"
    try:
        _, _, text = http(method, API + path, hd, body, timeout=40)
    except HttpError as e:
        if ok404 and e.status in (404, 409):
            return None
        msg = ""
        try:
            msg = json.loads(e.body).get("message", "")
        except ValueError:
            msg = e.body[:150]
        if e.status == 401:
            raise HTTPException(400, "GitHub 토큰이 만료됐거나 취소됐습니다. 다시 연결해 주세요.")
        if e.status == 403 and "rate limit" in msg.lower():
            raise HTTPException(429, "GitHub 요청 한도를 넘었습니다. 잠시 뒤에 다시 해 주세요.")
        if e.status in (403, 404) and method != "GET":
            raise HTTPException(403 if e.status == 403 else 404,
                                f"GitHub가 거절했습니다 ({e.status}): {msg}. 이 저장소에 쓰기 권한이 있는 계정의 토큰인지 확인하세요.")
        if e.status == 404:
            raise HTTPException(404, f"GitHub에서 찾을 수 없습니다: {path.split('?')[0]}")
        raise HTTPException(502, f"GitHub 요청 실패 ({e.status or '연결 안 됨'}): {msg}")
    if raw:
        return text
    return json.loads(text) if text.strip() else {}


def _chk(*names: str) -> None:
    for n in names:
        if not NAME.match(n or ""):
            raise HTTPException(400, "GitHub 이름이 올바르지 않습니다.")


def _safe_path(p: str) -> str:
    p = str(p or "").strip().lstrip("/")
    if not p or ".." in p.split("/") or p.startswith(".git/") or len(p) > 300 or "\\" in p or "\x00" in p:
        raise HTTPException(400, f"경로가 올바르지 않습니다: {p[:60]}")
    return p


def token_for(db: DB, owner: str) -> tuple[str, str]:
    """저장소 주인 계정의 토큰 → 없으면 .env GITHUB_TOKEN → 없으면 다른 연결 계정. (토큰, 어떤 것인지)"""
    toks = _tokens(db)
    low = {k.lower(): v for k, v in toks.items()}
    if owner.lower() in low:
        return low[owner.lower()]["token"], owner
    if config.GITHUB_TOKEN:
        return config.GITHUB_TOKEN, ".env GITHUB_TOKEN"
    for k, v in toks.items():
        return v["token"], k
    return "", ""


def _need_reauth(s: Session) -> None:
    if not recent_reauth(s):
        raise HTTPException(403, "reauth_required")


# ---------- 계정 연결 ----------
@router.get("/accounts")
def accounts(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    toks = _tokens(db)
    return {"accounts": [{"login": k, "via": v.get("via"), "added": v.get("added"), "scopes": v.get("scopes", "")} for k, v in toks.items()],
            "envToken": bool(config.GITHUB_TOKEN), "oauth": bool(config.GITHUB_OAUTH_ID and config.GITHUB_OAUTH_SECRET and config.PUBLIC_URL)}


def _save_token(db: DB, token: str, via: str) -> str:
    try:
        _, hd, text = http("GET", API + "/user", _h(token), timeout=20)
    except HttpError as e:
        raise HTTPException(400, f"토큰을 확인하지 못했습니다 ({e.status}). 복사한 값이 맞는지 확인하세요.")
    login = json.loads(text).get("login") or ""
    if not NAME.match(login):
        raise HTTPException(400, "GitHub 계정을 확인하지 못했습니다.")
    toks = _tokens(db)
    toks[login] = {"token": token, "via": via, "added": time.strftime("%Y-%m-%d %H:%M"), "scopes": hd.get("x-oauth-scopes", "")}
    kv_set(db, TOK_KEY, toks)
    return login


@router.post("/token")
def add_token(req: Request, payload: dict = Body(...), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    _need_reauth(s)
    token = str(payload.get("token") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{20,255}", token):
        raise HTTPException(400, "GitHub 토큰 형식이 아닙니다 (github_pat_… 또는 ghp_…).")
    login = _save_token(db, token, "토큰")
    audit(db, s.user_id, "gh_token_add", login, client_ip(req))
    return {"login": login}


@router.delete("/token/{login}")
def del_token(login: str, req: Request, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    _need_reauth(s)
    toks = _tokens(db)
    if login in toks:
        del toks[login]
        kv_set(db, TOK_KEY, toks)
        audit(db, s.user_id, "gh_token_del", login, client_ip(req))
    return {"ok": True}


@router.get("/oauth/start")
def oauth_start(s: Session = Depends(require_user), db: DB = Depends(get_db)):
    if not (config.GITHUB_OAUTH_ID and config.GITHUB_OAUTH_SECRET and config.PUBLIC_URL):
        raise HTTPException(400, "OAuth 앱 설정(GITHUB_OAUTH_ID·SECRET·PUBLIC_URL)이 .env에 없습니다. 토큰 붙여넣기로 연결하세요.")
    _need_reauth(s)
    state = secrets.token_urlsafe(24)
    kv_set(db, "gh_state:" + state[:40], {"exp": time.time() + 600, "uid": s.user_id})
    q = urllib.parse.urlencode({"client_id": config.GITHUB_OAUTH_ID, "redirect_uri": config.PUBLIC_URL + "/api/cms/oauth/callback",
                                "scope": "public_repo read:user", "state": state, "allow_signup": "false"})
    return {"url": "https://github.com/login/oauth/authorize?" + q}


@router.get("/oauth/callback")
def oauth_callback(req: Request, code: str = "", state: str = "", db: DB = Depends(get_db)):
    """GitHub에서 돌아오는 주소. SameSite=Strict 쿠키가 안 따라오므로 로그인 대신 1회용 state(10분)로 확인합니다."""
    key = "gh_state:" + state[:40]
    st = kv_get(db, key) if state else None
    kv_del(db, key)
    if not st or st.get("exp", 0) < time.time() or not re.fullmatch(r"[A-Za-z0-9_-]{4,100}", code or ""):
        return RedirectResponse("/cms?gh=fail", status_code=303)
    try:
        body = urllib.parse.urlencode({"client_id": config.GITHUB_OAUTH_ID, "client_secret": config.GITHUB_OAUTH_SECRET, "code": code,
                                       "redirect_uri": config.PUBLIC_URL + "/api/cms/oauth/callback"}).encode()
        _, _, text = http("POST", "https://github.com/login/oauth/access_token",
                          {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "juwon-os-cms"}, body)
        token = json.loads(text).get("access_token") or ""
        login = _save_token(db, token, "OAuth")
        audit(db, st.get("uid"), "gh_oauth", login, client_ip(req))
    except (HttpError, HTTPException, ValueError):
        return RedirectResponse("/cms?gh=fail", status_code=303)
    return RedirectResponse("/cms?gh=ok", status_code=303)


# ---------- 저장소 조회 ----------
@router.get("/repo/{owner}/{repo}/status")
def repo_status(owner: str, repo: str, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    _chk(owner, repo)
    tok, who = token_for(db, owner)
    info = _call("GET", f"/repos/{owner}/{repo}", tok)
    br = info.get("default_branch") or "main"
    commits = _call("GET", f"/repos/{owner}/{repo}/commits?per_page=12", tok, ok404=True) or []
    runs = (_call("GET", f"/repos/{owner}/{repo}/actions/runs?per_page=6", tok, ok404=True) or {}).get("workflow_runs") or []
    pages = _call("GET", f"/repos/{owner}/{repo}/pages", tok, ok404=True) if tok else None
    build = _call("GET", f"/repos/{owner}/{repo}/pages/builds/latest", tok, ok404=True) if tok else None
    tree = _call("GET", f"/repos/{owner}/{repo}/git/trees/{urllib.parse.quote(br)}?recursive=1", tok, ok404=True) or {}
    paths = [t["path"] for t in tree.get("tree") or [] if t.get("type") == "blob"]
    perm = info.get("permissions") or {}
    return {
        "name": info.get("full_name"), "branch": br, "url": info.get("html_url"), "homepage": info.get("homepage") or (pages or {}).get("html_url"),
        "private": info.get("private"), "push": bool(perm.get("push")), "tokenFrom": who or "(없음 · 읽기 전용)",
        "jekyll": "_config.yml" in paths, "chirpy": any(p.startswith("_tabs/") for p in paths),
        "posts": sorted([p for p in paths if p.startswith("_posts/")], reverse=True)[:400],
        "htmls": [p for p in paths if p.endswith(".html") and not p.startswith(("_", "assets/"))][:100],
        "images": len([p for p in paths if p.startswith("assets/img/")]),
        "commits": [{"sha": c["sha"][:7], "full": c["sha"], "msg": (c.get("commit") or {}).get("message", "").split("\n")[0][:160],
                     "date": ((c.get("commit") or {}).get("author") or {}).get("date"), "url": c.get("html_url")} for c in commits],
        "runs": [{"name": r.get("name"), "status": r.get("status"), "result": r.get("conclusion"), "date": r.get("created_at"),
                  "url": r.get("html_url"), "sha": (r.get("head_sha") or "")[:7], "event": r.get("event")} for r in runs],
        "pages": {"source": ((pages or {}).get("build_type")), "url": (pages or {}).get("html_url"), "status": (build or {}).get("status"),
                  "error": ((build or {}).get("error") or {}).get("message"), "date": (build or {}).get("updated_at")},
    }


@router.get("/repo/{owner}/{repo}/file")
def repo_file(owner: str, repo: str, path: str, ref: str = "", s: Session = Depends(require_user), db: DB = Depends(get_db)):
    _chk(owner, repo)
    path = _safe_path(path)
    if len(ref) > 100 or not re.fullmatch(r"[A-Za-z0-9_./-]*", ref):
        raise HTTPException(400, "ref가 올바르지 않습니다.")
    tok, _ = token_for(db, owner)
    q = f"?ref={urllib.parse.quote(ref)}" if ref else ""
    meta = _call("GET", f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}{q}", tok)
    if isinstance(meta, list):
        return {"path": path, "dir": [{"name": x["name"], "path": x["path"], "type": x["type"], "size": x.get("size")} for x in meta]}
    raw = base64.b64decode(meta.get("content") or "") if meta.get("encoding") == "base64" else b""
    if not raw and meta.get("size", 0) > 0:
        raw = _call("GET", f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}{q}", tok, raw=True).encode()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"path": path, "sha": meta.get("sha"), "binary": True, "size": meta.get("size")}
    return {"path": path, "sha": meta.get("sha"), "text": text[:400000], "size": meta.get("size")}


@router.get("/repo/{owner}/{repo}/history")
def repo_history(owner: str, repo: str, path: str, s: Session = Depends(require_user), db: DB = Depends(get_db)):
    _chk(owner, repo)
    path = _safe_path(path)
    tok, _ = token_for(db, owner)
    cs = _call("GET", f"/repos/{owner}/{repo}/commits?per_page=30&path={urllib.parse.quote(path)}", tok, ok404=True) or []
    return [{"sha": c["sha"], "msg": (c.get("commit") or {}).get("message", "").split("\n")[0][:160],
             "date": ((c.get("commit") or {}).get("author") or {}).get("date"), "url": c.get("html_url")} for c in cs]


# ---------- 커밋 (발행) ----------
@router.post("/repo/{owner}/{repo}/commit")
def commit(owner: str, repo: str, req: Request, payload: dict = Body(...), s: Session = Depends(require_user), db: DB = Depends(get_db)):
    """{"message": "...", "files": [{"path": "_posts/2026-11-17-a.md", "text": "..."} | {"path": ..., "fileId": "..."} | {"path": ..., "delete": true}],
        "branch": "" (비우면 기본 브랜치에 바로), "pr": {"title": "...", "body": "..."} (branch를 줄 때만)}
    여러 파일을 커밋 하나로 올립니다."""
    _chk(owner, repo)
    tok, who = token_for(db, owner)
    if not tok:
        raise HTTPException(400, "GitHub 계정이 연결되지 않았습니다. 'GitHub 연결'에서 이 저장소 계정의 토큰을 넣어 주세요.")
    msg = str(payload.get("message") or "").strip()[:300] or "Update via JUWON OS"
    files = payload.get("files") or []
    if not isinstance(files, list) or not files or len(files) > 80:
        raise HTTPException(400, "올릴 파일이 없거나 너무 많습니다 (최대 80개).")
    info = _call("GET", f"/repos/{owner}/{repo}", tok)
    if not (info.get("permissions") or {}).get("push"):
        raise HTTPException(403, f"{who} 토큰에는 {owner}/{repo} 쓰기 권한이 없습니다. 이 저장소 계정({owner})의 토큰을 연결하세요.")
    base = info.get("default_branch") or "main"
    branch = str(payload.get("branch") or "").strip()
    if branch and not re.fullmatch(r"[A-Za-z0-9._/-]{1,80}", branch):
        raise HTTPException(400, "브랜치 이름이 올바르지 않습니다.")
    ref = _call("GET", f"/repos/{owner}/{repo}/git/ref/heads/{urllib.parse.quote(base)}", tok)
    head = ref["object"]["sha"]
    base_tree = _call("GET", f"/repos/{owner}/{repo}/git/commits/{head}", tok)["tree"]["sha"]
    total, tree, done = 0, [], []
    for f in files:
        path = _safe_path((f or {}).get("path"))
        if f.get("delete"):
            tree.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
            done.append({"path": path, "op": "삭제"})
            continue
        if f.get("fileId"):
            sf = db.get(StoredFile, str(f["fileId"]))
            if not sf or sf.vault:
                raise HTTPException(400, f"올릴 수 없는 파일입니다: {path}")
            with open(os.path.join(config.FILES_DIR, sf.path), "rb") as fp:
                data = fp.read()
        else:
            data = str(f.get("text") or "").encode("utf-8")
        total += len(data)
        if total > MAX_COMMIT_BYTES:
            raise HTTPException(413, "한 번에 올리는 파일이 40MB를 넘습니다. 이미지를 줄이거나 나눠 올리세요.")
        blob = _call("POST", f"/repos/{owner}/{repo}/git/blobs", tok, {"content": base64.b64encode(data).decode(), "encoding": "base64"})
        tree.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
        done.append({"path": path, "op": "올림", "bytes": len(data)})
    new_tree = _call("POST", f"/repos/{owner}/{repo}/git/trees", tok, {"base_tree": base_tree, "tree": tree})
    c = _call("POST", f"/repos/{owner}/{repo}/git/commits", tok, {"message": msg, "tree": new_tree["sha"], "parents": [head]})
    pr_url = ""
    if branch and branch != base:
        exists = _call("GET", f"/repos/{owner}/{repo}/git/ref/heads/{urllib.parse.quote(branch)}", tok, ok404=True)
        if exists:
            _call("PATCH", f"/repos/{owner}/{repo}/git/refs/heads/{urllib.parse.quote(branch)}", tok, {"sha": c["sha"], "force": True})
        else:
            _call("POST", f"/repos/{owner}/{repo}/git/refs", tok, {"ref": f"refs/heads/{branch}", "sha": c["sha"]})
        pr = payload.get("pr") or None
        if pr:
            got = _call("GET", f"/repos/{owner}/{repo}/pulls?state=open&head={urllib.parse.quote(owner + ':' + branch)}", tok) or []
            if got:
                pr_url = got[0].get("html_url", "")
            else:
                p = _call("POST", f"/repos/{owner}/{repo}/pulls", tok, {"title": str(pr.get("title") or msg)[:200], "head": branch, "base": base,
                                                                          "body": str(pr.get("body") or "")[:4000]})
                pr_url = p.get("html_url", "")
    else:
        branch = base
        _call("PATCH", f"/repos/{owner}/{repo}/git/refs/heads/{urllib.parse.quote(base)}", tok, {"sha": c["sha"], "force": False})
    audit(db, s.user_id, "gh_commit", f"{owner}/{repo}@{branch} {c['sha'][:7]} {len(done)} files", client_ip(req))
    return {"sha": c["sha"], "url": f"https://github.com/{owner}/{repo}/commit/{c['sha']}", "branch": branch, "pr": pr_url, "files": done, "by": who}
