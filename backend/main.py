"""
CyberTrust Decision Engine (CTDE) — FastAPI Application Entry Point
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from database import init_db
from routers import investigation, assistant, reports, users

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Startup / Shutdown ────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s v%s", settings.APP_NAME, settings.APP_VERSION)
    init_db()
    logger.info("Database initialized")
    _log_api_key_status()
    yield
    logger.info("CTDE backend shutting down")


def _log_api_key_status():
    keys = {
        "VirusTotal": settings.VIRUSTOTAL_API_KEY,
        "Google Safe Browsing": settings.GOOGLE_SAFE_BROWSING_API_KEY,
        "URLScan.io": settings.URLSCAN_API_KEY,
        "AbuseIPDB": settings.ABUSEIPDB_API_KEY,
        "OpenAI": settings.OPENAI_API_KEY,
        "Google AI (Gemini)": settings.GOOGLE_API_KEY,
    }
    for name, key in keys.items():
        status = "CONFIGURED" if key else "not configured (graceful fallback active)"
        logger.info("  %-25s %s", name + ":", status)


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-powered Digital Trust and Digital Forensics platform.",
    lifespan=lifespan,
)

# CORS — allow the Vite dev server and any deployed frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "*",  # remove in production and list explicit origins
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global error handlers ─────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(investigation.router)
app.include_router(assistant.router)
app.include_router(reports.router)
app.include_router(users.router)


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["system"])
async def health():
    return {
        "status": "operational",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "apis": {
            "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
            "googleSafeBrowsing": bool(settings.GOOGLE_SAFE_BROWSING_API_KEY),
            "urlscan": bool(settings.URLSCAN_API_KEY),
            "abuseipdb": bool(settings.ABUSEIPDB_API_KEY),
            "openai": bool(settings.OPENAI_API_KEY),
            "gemini": bool(settings.GOOGLE_API_KEY),
        },
    }
