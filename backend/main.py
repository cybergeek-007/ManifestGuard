from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

_env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(_env_path)

from backend.api import router

app = FastAPI(
    title="ManifestGuard API",
    version="4.0.0",
    summary="Browser extension security auditing with reputation engine, behavioral analysis, and safe alternative recommendations.",
)

_raw_origins = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,chrome-extension://nmlkkglnnkgigimofnhmbdnpmnimldif",
)
# Robust parse: drop blanks and trailing slashes so a stray comma/space in the
# env var can never silently disable CORS for a valid frontend origin.
allowed_origins = [o.strip().rstrip("/") for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "Origin", "X-Requested-With",
                    "X-AI-Provider", "X-AI-Api-Key", "X-AI-Model",
                    "X-AI-Base-Url", "X-AI-Account-Id"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a JSON 500 (which the CORS middleware will decorate) instead of
    letting an unhandled error bubble up as a raw worker crash. A raw crash on
    the host produces a proxy 502 with no CORS headers, which the browser then
    misreports as a CORS error rather than the real server-side failure.
    """
    return JSONResponse(
        status_code=500,
        content={"detail": "Scan failed due to an internal server error. Please try again."},
    )


app.include_router(router)

