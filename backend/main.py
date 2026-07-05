from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

_env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(_env_path)

from backend.api import router

app = FastAPI(
    title="ManifestGuard API",
    version="4.0.0",
    summary="Browser extension security auditing with reputation engine, behavioral analysis, and safe alternative recommendations.",
)

allowed_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173,chrome-extension://nmlkkglnnkgigimofnhmbdnpmnimldif").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "Origin", "X-Requested-With",
                    "X-AI-Provider", "X-AI-Api-Key", "X-AI-Model",
                    "X-AI-Base-Url", "X-AI-Account-Id"],
)

app.include_router(router)

