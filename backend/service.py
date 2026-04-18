from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from backend.ai import maybe_enrich_with_ai
from backend.models import ExtensionFinding, ScanOptions, ScanRecord
from backend.reports import (
    write_csv_report,
    write_html_report,
    write_json_report,
    write_pdf_report,
)
from backend.scanner import import_legacy_csv, scan_local_extensions


class ScanService:
    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = data_dir or Path("backend") / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._scans: dict[str, ScanRecord] = {}
        self._load_existing_scans()

    def _load_existing_scans(self) -> None:
        for report_file in sorted(self.data_dir.glob("*/*.json")):
            try:
                payload = report_file.read_text(encoding="utf-8")
                record = ScanRecord.from_dict(json.loads(payload), report_file.parent)
            except Exception:
                continue
            self._scans[record.scan_id] = record

    def create_scan(self, options: ScanOptions) -> ScanRecord:
        scan_id = uuid.uuid4().hex[:12]
        findings = scan_local_extensions(options)
        maybe_enrich_with_ai(findings, options.enable_ai)
        report_dir = self.data_dir / scan_id
        report_dir.mkdir(parents=True, exist_ok=True)
        record = ScanRecord(
            scan_id=scan_id,
            created_at=datetime.now(timezone.utc),
            status="completed",
            source="local_scan",
            options=options,
            findings=findings,
            report_dir=report_dir,
        )
        self._scans[scan_id] = record
        write_json_report(record, report_dir / f"{scan_id}.json")
        return record

    def import_csv_report(self, filename: str, content: bytes) -> ScanRecord:
        scan_id = uuid.uuid4().hex[:12]
        findings = import_legacy_csv(filename, content)
        record = ScanRecord(
            scan_id=scan_id,
            created_at=datetime.now(timezone.utc),
            status="completed",
            source="csv_import",
            options=ScanOptions(),
            findings=findings,
            report_dir=self.data_dir / scan_id,
        )
        record.report_dir.mkdir(parents=True, exist_ok=True)
        self._scans[scan_id] = record
        write_json_report(record, record.report_dir / f"{scan_id}.json")
        return record

    def list_scans(self) -> list[ScanRecord]:
        return sorted(self._scans.values(), key=lambda scan: scan.created_at, reverse=True)

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        return self._scans.get(scan_id)

    def get_extension(self, scan_id: str, extension_id: str) -> ExtensionFinding | None:
        scan = self.get_scan(scan_id)
        if not scan:
            return None
        for finding in scan.findings:
            if finding.id == extension_id:
                return finding
        return None

    def export_report(self, scan_id: str, format_name: str) -> Path | None:
        scan = self.get_scan(scan_id)
        if not scan:
            return None

        format_name = format_name.lower()
        destination = scan.report_dir / f"{scan_id}.{format_name}"
        if format_name == "csv":
            return write_csv_report(scan, destination)
        if format_name == "json":
            return write_json_report(scan, destination)
        if format_name == "html":
            return write_html_report(scan, destination)
        if format_name == "pdf":
            return write_pdf_report(scan, destination)
        raise ValueError("Unsupported report format")


service = ScanService()
