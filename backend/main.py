"""
VPN Control Panel — FastAPI backend

Production start (single process):
    uvicorn backend.main:app --host 0.0.0.0 --port 8000

Development start:
    uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

⚠  Do NOT use --workers > 1.  storage.py uses threading.Lock which is
   per-process only; multiple workers will cause concurrent JSON writes,
   lost data, and IP double-allocation.
"""
import logging
import sys
from pathlib import Path

# Put backend/ on sys.path so sibling modules import without package prefix
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

# Configure logging before any application imports
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)-26s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from auth import verify_token
from storage import init_storage
from routes.auth      import router as auth_router
from routes.users     import router as users_router
from routes.devices   import router as devices_router
from routes.downloads import router as downloads_router
from routes.wg_status import router as wg_status_router

FRONTEND    = Path(__file__).parent.parent / "frontend" / "index.html"
PUBLIC_PATHS = {"/api/auth/login", "/health", "/"}


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_storage()
    log.info("VPN Control Panel started")
    yield
    log.info("VPN Control Panel shutting down")


app = FastAPI(title="VPN Control Panel", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Exception handlers ────────────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"ok": False, "error": exc.detail},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log.error(
        f"Unhandled exception: {request.method} {request.url.path} — {exc}",
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"ok": False, "error": "Internal server error"},
    )


# ── Auth middleware ───────────────────────────────────────────────────────────

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path in PUBLIC_PATHS or not request.url.path.startswith("/api"):
        return await call_next(request)
    token = request.headers.get("X-API-TOKEN", "")
    if not token or not verify_token(token):
        return JSONResponse(
            status_code=401,
            content={"ok": False, "error": "Unauthorized — invalid or expired token"},
        )
    return await call_next(request)


# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(auth_router,      prefix="/api/auth",       tags=["auth"])
app.include_router(users_router,     prefix="/api/users",      tags=["users"])
app.include_router(devices_router,   prefix="/api/devices",    tags=["devices"])
app.include_router(downloads_router, prefix="/api/downloads",  tags=["downloads"])
app.include_router(wg_status_router, prefix="/api/wireguard",  tags=["wireguard"])


# ── Static / health ───────────────────────────────────────────────────────────

@app.get("/")
async def serve_frontend():
    if not FRONTEND.exists():
        return JSONResponse({"ok": False, "error": "Frontend not found"}, status_code=404)
    return FileResponse(FRONTEND)


@app.get("/health")
def health():
    return {"ok": True, "data": {"status": "ok"}}
