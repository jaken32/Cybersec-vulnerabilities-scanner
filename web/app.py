"""FastAPI application: routes, rate limiting, security headers, consent logging.

Run with::

    uvicorn web.app:app --host 127.0.0.1 --port 8000

The app is hardened to score an A on its own scanner: strict CSP (no inline
script/style — all assets are external and same-origin), HSTS, nosniff,
Referrer-Policy, Permissions-Policy, frame protection, no version banners, and no
insecure cookies.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from scanner import __version__
from scanner.engine import scan
from scanner.models import ScanResult
from scanner.reporting.html import render_report
from scanner.safety.ssrf import SSRFError

# ---------------------------------------------------------------------------
# Configuration (all via environment; see .env.example)
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


RATE_LIMIT = os.getenv("WEBSEC_RATE_LIMIT", "10/minute")
TARGET_COOLDOWN = _int_env("WEBSEC_TARGET_COOLDOWN_SECONDS", 30)
SCAN_TIMEOUT = float(os.getenv("WEBSEC_SCAN_TIMEOUT", "12"))
MAX_BYTES = _int_env("WEBSEC_MAX_RESPONSE_BYTES", 5 * 1024 * 1024)
ENABLE_HSTS = os.getenv("WEBSEC_ENABLE_HSTS", "true").lower() != "false"
RESULT_TTL = _int_env("WEBSEC_RESULT_TTL_SECONDS", 1800)

logging.basicConfig(level=os.getenv("WEBSEC_LOG_LEVEL", "INFO"))
consent_log = logging.getLogger("websec.consent")

# ---------------------------------------------------------------------------
# App + middleware
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT])
app = FastAPI(title="websec-scanner", version=__version__, docs_url=None, redoc_url=None)
app.state.limiter = limiter

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.autoescape = True
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# In-memory stores. For a single-process deployment this is sufficient; behind
# multiple workers use a shared store (Redis) instead.
_target_last_seen: dict[str, float] = {}
_results: dict[str, tuple[float, ScanResult]] = {}

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if ENABLE_HSTS:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    # Replace the framework's version banner with a version-less token.
    response.headers["Server"] = "websec-scanner"
    if "x-powered-by" in response.headers:
        del response.headers["x-powered-by"]
    return response


@app.exception_handler(RateLimitExceeded)
async def ratelimit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded. Please wait a moment before scanning "
            "again."
        },
    )


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    url: str
    authorized: bool = False
    server: str | None = None

    @field_validator("url")
    @classmethod
    def _url_nonempty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("URL is required.")
        if len(v) > 2048:
            raise ValueError("URL is too long.")
        return v.strip()

    @field_validator("server")
    @classmethod
    def _server_valid(cls, v):
        if v in (None, "", "auto"):
            return None
        if v not in ("nginx", "apache", "cloudflare", "generic"):
            raise ValueError("Invalid server selection.")
        return v


def _prune_results() -> None:
    now = time.time()
    stale = [k for k, (ts, _) in _results.items() if now - ts > RESULT_TTL]
    for k in stale:
        _results.pop(k, None)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request, "index.html", {"version": __version__}
    )


@app.get("/healthz", response_class=PlainTextResponse)
async def healthz():
    return "ok"


@app.post("/api/scan")
@limiter.limit(RATE_LIMIT)
async def api_scan(request: Request):
    # Parse + validate body.
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400, content={"error": "Request body must be valid JSON."}
        )
    try:
        req = ScanRequest(**payload)
    except Exception as exc:  # pydantic ValidationError -> user-safe message
        msg = "Invalid request."
        try:
            msg = exc.errors()[0]["msg"]  # type: ignore[attr-defined]
        except Exception:
            pass
        return JSONResponse(status_code=400, content={"error": msg})

    # Authorization gate.
    if not req.authorized:
        return JSONResponse(
            status_code=400,
            content={
                "error": "You must confirm you are authorized to scan this target "
                "before a scan can run."
            },
        )

    client_ip = get_remote_address(request)

    # Per-target cooldown (defends targets and our egress from hammering).
    now = time.time()
    key = req.url.lower()
    last = _target_last_seen.get(key)
    if last is not None and (now - last) < TARGET_COOLDOWN:
        wait = int(TARGET_COOLDOWN - (now - last))
        return JSONResponse(
            status_code=429,
            content={
                "error": f"This target was scanned recently. Please wait about "
                f"{wait}s before scanning it again."
            },
        )
    _target_last_seen[key] = now

    # Consent logging with timestamp.
    consent_log.info(
        "CONSENT ip=%s target=%s authorized=%s ts=%s",
        client_ip,
        req.url,
        req.authorized,
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
    )

    async def event_stream():
        queue: asyncio.Queue = asyncio.Queue()

        def on_progress(pct: int, message: str) -> None:
            queue.put_nowait({"type": "progress", "pct": pct, "message": message})

        async def runner():
            try:
                result = await scan(
                    req.url,
                    timeout=SCAN_TIMEOUT,
                    max_bytes=MAX_BYTES,
                    server_override=req.server,
                    on_progress=on_progress,
                )
                _prune_results()
                rid = secrets.token_urlsafe(16)
                _results[rid] = (time.time(), result)
                queue.put_nowait(
                    {"type": "result", "id": rid, "result": result.to_dict()}
                )
            except SSRFError as exc:
                queue.put_nowait({"type": "error", "message": str(exc)})
            except Exception as exc:  # noqa: BLE001
                consent_log.exception("scan failed: %s", exc)
                queue.put_nowait(
                    {
                        "type": "error",
                        "message": "The scan could not be completed. Check the URL "
                        "and try again.",
                    }
                )
            finally:
                queue.put_nowait(None)

        task = asyncio.create_task(runner())
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield json.dumps(item) + "\n"
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(
        event_stream(),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@app.get("/report/{result_id}")
async def download_report(result_id: str):
    _prune_results()
    entry = _results.get(result_id)
    if entry is None:
        return PlainTextResponse(
            "Report not found or expired. Please run the scan again.", status_code=404
        )
    _, result = entry
    html = render_report(result)
    # Build a safe filename from the host only.
    safe = "".join(c for c in result.target if c.isalnum() or c in ".-")[:60] or "report"
    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'attachment; filename="websec-report-{safe}.html"'
        },
    )
