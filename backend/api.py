"""ManifestGuard v4 — API Routes.

Online-only. Local scan (POST /api/scans) and CSV import removed.
Deep scan is always on — the enableDeepScan option is accepted but ignored.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

from backend.service import service

_EXT_ID_RE = re.compile(r"^[a-p]{32}$")
_SCAN_ID_RE = re.compile(r"^[a-f0-9]{12,32}$")
_VALID_FORMATS = frozenset({"csv", "json", "html", "pdf"})

router = APIRouter(prefix="/api", tags=["manifestguard"])


class OnlineExtensionData(BaseModel):
    id: str
    name: str = "Unknown"
    version: str = ""
    description: str = ""
    permissions: list[str] = Field(default_factory=list)
    hostPermissions: list[str] = Field(default_factory=list)
    enabled: bool = True
    installType: str = "normal"
    homepageUrl: str = ""
    updateUrl: str = ""

    @field_validator("id")
    @classmethod
    def validate_extension_id(cls, v: str) -> str:
        if not _EXT_ID_RE.match(v):
            raise ValueError(f"Invalid extension ID format: must be 32 lowercase a-p chars")
        return v


class OnlineScanRequest(BaseModel):
    extensions: list[OnlineExtensionData]
    activeUrls: list[str] = Field(default_factory=list)
    enableAi: bool = False
    enableDeepScan: bool = True  # v4: always on, kept for backward compat

    @field_validator("extensions")
    @classmethod
    def validate_extension_count(cls, v: list) -> list:
        if len(v) > 100:
            raise ValueError("Too many extensions (max 100)")
        if len(v) == 0:
            raise ValueError("At least one extension is required")
        return v


@router.get("/health")
def healthcheck() -> dict[str, str]:
    return {"status": "ok", "version": "4.0.0"}


@router.post("/scans/online")
def create_online_scan(payload: OnlineScanRequest, request: Request) -> dict:
    """Accept extension metadata from companion browser extension.

    Downloads CRX from Google servers for deep source code analysis.
    Runs collusion graph, intel burst, and delta cache analysis.
    Deep scan is always enabled in v4.
    """
    extensions_data = [
        {
            "id": ext.id,
            "name": ext.name,
            "version": ext.version,
            "description": ext.description,
            "permissions": ext.permissions,
            "hostPermissions": ext.hostPermissions,
            "enabled": ext.enabled,
            "installType": ext.installType,
            "homepageUrl": ext.homepageUrl,
        }
        for ext in payload.extensions
    ]
    ai_config = _extract_ai_config(request)
    scan = service.create_online_scan(
        extensions_data,
        active_urls=payload.activeUrls,
        enable_ai=payload.enableAi,
        ai_config=ai_config,
    )
    return scan.to_summary_dict()


class SingleScanRequest(BaseModel):
    extensionId: str
    enableAi: bool = False

    @field_validator("extensionId")
    @classmethod
    def validate_extension_id(cls, v: str) -> str:
        if not _EXT_ID_RE.match(v):
            raise ValueError("Invalid extension ID format: must be 32 lowercase a-p chars")
        return v


@router.post("/scans/single")
def create_single_scan(req: SingleScanRequest, request: Request):
    ai_config = _extract_ai_config(request)
    result = service.create_single_extension_scan(req.extensionId, req.enableAi, ai_config=ai_config)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


class LocalScanRequest(BaseModel):
    enableAi: bool = False


@router.post("/scans/local")
def create_local_scan(req: LocalScanRequest, request: Request):
    try:
        ai_config = _extract_ai_config(request)
        result = service.create_local_scan(req.enableAi, ai_config=ai_config)
        return result.to_summary_dict()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))



@router.get("/scans")
def list_scans() -> list[dict]:
    return [scan.to_summary_dict() for scan in service.list_scans()]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    if not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    scan = service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.to_detail_dict()


@router.get("/scans/{scan_id}/extensions")
def get_scan_extensions(scan_id: str) -> list[dict]:
    if not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    scan = service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return [finding.to_inventory_dict() for finding in scan.findings]


@router.get("/scans/{scan_id}/extensions/{extension_id}")
def get_extension(scan_id: str, extension_id: str) -> dict:
    if not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    finding = service.get_extension(scan_id, extension_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Extension not found")
    return finding.to_detail_dict()


class ChatPayload(BaseModel):
    message: str = Field(..., min_length=1, max_length=1000)


@router.post("/scans/{scan_id}/extensions/{extension_id}/chat")
async def chat_with_extension_ai(scan_id: str, extension_id: str, payload: ChatPayload, request: Request) -> dict:
    if not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    finding = service.get_extension(scan_id, extension_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Extension not found")

    ai_config = _extract_ai_config(request)
    from backend.ai import chat_about_extension
    reply = await chat_about_extension(finding.to_detail_dict(), payload.message, ai_config)
    return {"reply": reply}



@router.get("/scans/{scan_id}/extensions/{extension_id}/recommendations")
def get_recommendations(scan_id: str, extension_id: str) -> list[dict]:
    """Get safe alternative recommendations for a flagged extension."""
    if not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    finding = service.get_extension(scan_id, extension_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Extension not found")
    return finding.recommendations




@router.get("/scans/{scan_id}/reports/{format_name}")
def get_report(scan_id: str, format_name: str) -> FileResponse:
    if not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    if format_name not in _VALID_FORMATS:
        raise HTTPException(status_code=400, detail=f"Invalid format. Must be one of: {', '.join(_VALID_FORMATS)}")

    try:
        report = service.export_report(scan_id, format_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not report:
        raise HTTPException(status_code=404, detail="Scan not found")

    media_types = {
        "csv": "text/csv",
        "json": "application/json",
        "html": "text/html",
        "pdf": "application/pdf",
    }
    return FileResponse(
        report,
        media_type=media_types.get(format_name, "application/octet-stream"),
        filename=report.name,
    )


# ── Watchlist / continuous monitoring ───────────────────────


class WatchlistAddRequest(BaseModel):
    extensionId: str

    @field_validator("extensionId")
    @classmethod
    def validate_extension_id(cls, v: str) -> str:
        if not _EXT_ID_RE.match(v):
            raise ValueError("Invalid extension ID format: must be 32 lowercase a-p chars")
        return v


@router.get("/watchlist")
def list_watchlist() -> list[dict]:
    return service.watchlist_all()


@router.post("/watchlist")
def add_to_watchlist(req: WatchlistAddRequest) -> dict:
    result = service.watchlist_add(req.extensionId)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.delete("/watchlist/{extension_id}")
def remove_from_watchlist(extension_id: str) -> dict:
    if not _EXT_ID_RE.match(extension_id):
        raise HTTPException(status_code=400, detail="Invalid extension ID format")
    return service.watchlist_remove(extension_id)


@router.post("/watchlist/{extension_id}/check")
def check_watched_extension(extension_id: str) -> dict:
    if not _EXT_ID_RE.match(extension_id):
        raise HTTPException(status_code=400, detail="Invalid extension ID format")
    result = service.watchlist_check(extension_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/watchlist/check-all")
def check_all_watched() -> list[dict]:
    return service.watchlist_check_all()


# ── Public stats ────────────────────────────────────────────


@router.get("/stats")
def public_stats() -> dict:
    """Aggregate stats for the landing/fleet overview (no PII)."""
    from backend.database import database
    return database.scan_stats()


# ── AI provider settings ────────────────────────────────────


def _extract_ai_config(request: Request) -> dict[str, str] | None:
    """Extract AI provider config from request headers.

    Users send their API key and provider choice via headers so keys
    are never persisted on the server.
    """
    api_key = request.headers.get("x-ai-api-key", "")
    if not api_key:
        return None
    return {
        "provider": request.headers.get("x-ai-provider", "custom"),
        "api_key": api_key,
        "model": request.headers.get("x-ai-model", ""),
        "base_url": request.headers.get("x-ai-base-url", ""),
        "account_id": request.headers.get("x-ai-account-id", ""),
    }


class AITestPayload(BaseModel):
    provider: str
    apiKey: str
    model: str = ""
    baseUrl: str = ""
    accountId: str = ""


@router.post("/settings/ai/test")
async def test_ai_provider(payload: AITestPayload) -> dict:
    """Test a user-provided AI provider connection."""
    from backend.ai import test_ai_connection
    ai_config = {
        "provider": payload.provider,
        "api_key": payload.apiKey,
        "model": payload.model,
        "base_url": payload.baseUrl,
        "account_id": payload.accountId,
    }
    return await test_ai_connection(ai_config)


@router.get("/settings/ai/providers")
def list_ai_providers() -> list[dict]:
    """Return available AI provider presets."""
    from backend.ai import PROVIDER_PRESETS
    return [
        {"id": pid, "baseUrl": preset["base_url"], "defaultModel": preset["default_model"]}
        for pid, preset in PROVIDER_PRESETS.items()
    ]
