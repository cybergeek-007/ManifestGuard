from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api import router

app = FastAPI(
    title="ManifestGuard API",
    version="2.0.0",
    summary="Local-first browser extension auditing with evidence-based classification.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

