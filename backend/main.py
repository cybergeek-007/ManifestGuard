from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api import router

app = FastAPI(
    title="ManifestGuard API",
    version="3.0.0",
    summary="Browser extension security auditing with reputation engine, behavioral analysis, and safe alternative recommendations.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

