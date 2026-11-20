import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import config
from .auth import router as auth_router
from .db import Base, engine
from .files import router as files_router
from .records import router as records_router
from .kis import router as kis_router
from .codef import router as codef_router
from .statement import router as statement_router
from .erp import router as erp_router
from .ghcms import router as cms_router
from .kiwoom import router as kiwoom_router
from .github import router as github_router
from .autotrade import router as autotrade_router
from .assets import router as assets_router
from .bundle import router as bundle_router
from .feeds import router as feeds_router
from .scheduler import start as start_scheduler

app = FastAPI(title="JUWON OS API", version="2.0.0", docs_url=None, redoc_url=None, openapi_url=None)


@app.on_event("startup")
def startup() -> None:
    os.makedirs(config.FILES_DIR, exist_ok=True)
    Base.metadata.create_all(engine)
    start_scheduler()


@app.middleware("http")
async def security_headers(req: Request, call_next):
    resp = await call_next(req)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if req.url.path.startswith("/api/") and not req.url.path.startswith("/api/files/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.exception_handler(Exception)
async def unhandled(req: Request, exc: Exception):
    # 내부 오류 내용은 로그에만 남기고 화면에는 짧게
    import logging
    logging.exception("unhandled error on %s", req.url.path)
    # 혼자 쓰는 사설 서버라 원인 파악을 위해 오류 종류와 짧은 내용을 화면에도 보여 줌 (비밀값은 들어가지 않음)
    msg = str(exc).replace(config.FIELD_KEY, "***")[:220]
    return JSONResponse({"detail": f"서버 오류 ({type(exc).__name__}): {msg}"}, status_code=500)


@app.get("/api/health")
def health():
    return {"ok": True}


app.include_router(auth_router)
app.include_router(records_router)
app.include_router(files_router)
app.include_router(kis_router)
app.include_router(kiwoom_router)
app.include_router(github_router)
app.include_router(autotrade_router)
app.include_router(assets_router)
app.include_router(bundle_router)
app.include_router(feeds_router)
app.include_router(codef_router)
app.include_router(statement_router)
app.include_router(erp_router)
app.include_router(cms_router)
