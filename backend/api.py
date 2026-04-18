from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.service import ScanOptions, ScanService, service

router = APIRouter(prefix="/api", tags=["manifestguard"])


class ScanRequest(BaseModel):
    profiles: list[str] = Field(default_factory=list)
    channels: list[str] = Field(default_factory=list)
    enableLiveChecks: bool = False
    enableAi: bool = False


def _map_options(payload: ScanRequest) -> ScanOptions:
    return ScanOptions(
        profiles=payload.profiles or None,
        channels=payload.channels or None,
        enable_live_checks=payload.enableLiveChecks,
        enable_ai=payload.enableAi,
    )


@router.get("/health")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/scans")
def create_scan(payload: ScanRequest) -> dict:
    scan = service.create_scan(_map_options(payload))
    return scan.to_summary_dict()


@router.get("/scans")
def list_scans() -> list[dict]:
    return [scan.to_summary_dict() for scan in service.list_scans()]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    scan = service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.to_detail_dict()


@router.get("/scans/{scan_id}/extensions")
def get_scan_extensions(scan_id: str) -> list[dict]:
    scan = service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return [finding.to_inventory_dict() for finding in scan.findings]


@router.get("/scans/{scan_id}/extensions/{extension_id}")
def get_extension(scan_id: str, extension_id: str) -> dict:
    finding = service.get_extension(scan_id, extension_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Extension not found")
    return finding.to_detail_dict()


@router.get("/scans/{scan_id}/reports/{format_name}")
def get_report(scan_id: str, format_name: str) -> FileResponse:
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


@router.post("/imports/csv")
async def import_csv(file: UploadFile = File(...)) -> dict:
    content = await file.read()
    scan = service.import_csv_report(file.filename or "extensions.csv", content)
    return scan.to_detail_dict()
