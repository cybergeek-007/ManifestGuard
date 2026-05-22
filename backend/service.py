from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.ai import maybe_enrich_with_ai
from backend.models import ExtensionFinding, ProfileInstall, ScanOptions, ScanRecord
from backend.reports import (
    write_csv_report,
    write_html_report,
    write_json_report,
    write_pdf_report,
)
from backend.scanner import scan_local_extensions


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

    def create_online_scan(
        self,
        extensions_data: list[dict[str, Any]],
        enable_ai: bool = False,
        enable_deep_scan: bool = False,
    ) -> ScanRecord:
        """Create a scan from companion extension metadata.

        For each extension:
        1. Check allowlist → check threat intel → fetch reputation
        2. If enable_deep_scan: download CRX from Google, extract, analyze source
        3. Score using the retuned engine
        4. Generate recommendations for flagged extensions
        """
        from backend.allowlist import is_trusted
        from backend.crx_analyzer import cleanup_extraction, download_and_extract
        from backend.intel import lookup_intel
        from backend.recommendations import get_recommendations
        from backend.reputation import compute_reputation_adjustment, fetch_reputation
        from backend.scanner import (
            analyze_codebase,
            choose_verdict,
            compute_power_score,
            compute_suspicion_score,
            infer_category,
        )
        from backend.store import lookup_store_status

        scan_id = uuid.uuid4().hex[:12]
        findings: list[ExtensionFinding] = []

        for ext in extensions_data:
            ext_id = ext["id"]
            name = ext.get("name", "Unknown")
            description = ext.get("description", "")
            version = ext.get("version", "unknown")
            permissions = ext.get("permissions", [])
            host_permissions = ext.get("hostPermissions", [])
            enabled = ext.get("enabled", True)
            install_type = ext.get("installType", "normal")

            # 1. Threat intel check
            intel_matches = lookup_intel(ext_id)

            # 2. Store status
            store_status = lookup_store_status(ext_id).status

            # 3. Reputation
            reputation_score = -1
            reputation_details = None
            try:
                rep = fetch_reputation(ext_id)
                if rep.lookup_status == "success":
                    reputation_score = rep.reputation_score
                    reputation_details = rep.to_dict()
            except Exception:
                pass

            # 4. Category inference
            category = infer_category(name, description, permissions)

            # 5. Power score
            power_score = compute_power_score(permissions, host_permissions)

            # 6. Source code analysis (if deep scan enabled)
            signals = []
            timeline = []
            if enable_deep_scan and install_type != "development":
                try:
                    crx_result = download_and_extract(ext_id)
                    if crx_result.success and crx_result.extract_dir:
                        manifest = crx_result.manifest or {}
                        signals, timeline = analyze_codebase(
                            crx_result.extract_dir, manifest, permissions, host_permissions
                        )
                        cleanup_extraction(crx_result.extract_dir)
                    else:
                        timeline.append(f"CRX analysis skipped: {crx_result.error}")
                except Exception as e:
                    timeline.append(f"CRX analysis error: {str(e)[:100]}")

            if not timeline:
                timeline.append("Online scan — metadata analysis only.")

            # 7. Suspicion score
            raw_suspicion = compute_suspicion_score(
                signals, len(intel_matches), store_status,
                extension_id=ext_id, category=category, permissions=permissions,
            )

            # Apply reputation adjustment
            if reputation_score >= 0:
                adjustment = compute_reputation_adjustment(reputation_score)
                adjusted_suspicion = int(raw_suspicion * adjustment)
            else:
                adjusted_suspicion = raw_suspicion

            suspicion_score = min(adjusted_suspicion, 100)

            # 8. Verdict
            enabled_state = "enabled" if enabled else "disabled"
            verdict = choose_verdict(
                enabled_state, power_score, suspicion_score, len(intel_matches),
                store_status, extension_id=ext_id, reputation_score=reputation_score,
            )

            # 9. Recommendations for flagged extensions
            recommendations: list[dict] = []
            if verdict in ("suspicious", "moderate_risk", "known_malicious"):
                try:
                    recs = get_recommendations(name, description, category)
                    recommendations = [r.to_dict() for r in recs]
                except Exception:
                    pass

            # Build finding
            finding = ExtensionFinding(
                id=ext_id,
                name=name,
                version=version,
                description=description,
                manifest_version=0,
                permissions=permissions,
                optional_permissions=[],
                host_permissions=host_permissions,
                optional_host_permissions=[],
                content_script_matches=[],
                profiles=[
                    ProfileInstall(
                        profile_id="online",
                        profile_name="Browser Scan",
                        browser_channel="online",
                        browser_family="chromium",
                        enabled_state=enabled_state,
                        install_source=install_type,
                        version=version,
                        manifest_path="",
                    )
                ],
                power_score=power_score,
                suspicion_score=suspicion_score,
                verdict=verdict,
                store_status=store_status,
                suspicious_signals=signals,
                intel_matches=intel_matches,
                evidence_timeline=timeline,
                homepage_url=ext.get("homepageUrl"),
                category=category,
                reputation_score=reputation_score,
                reputation_details=reputation_details,
                adjusted_suspicion_score=suspicion_score,
                recommendations=recommendations,
            )
            findings.append(finding)

        # Enrich with AI if requested
        maybe_enrich_with_ai(findings, enable_ai)

        # Sort by risk
        findings.sort(
            key=lambda f: (
                f.verdict != "known_malicious",
                -f.suspicion_score,
                -f.power_score,
                f.name.lower(),
            )
        )

        report_dir = self.data_dir / scan_id
        report_dir.mkdir(parents=True, exist_ok=True)
        record = ScanRecord(
            scan_id=scan_id,
            created_at=datetime.now(timezone.utc),
            status="completed",
            source="online_scan",
            options=ScanOptions(enable_live_checks=True, enable_ai=enable_ai),
            findings=findings,
            report_dir=report_dir,
        )
        self._scans[scan_id] = record
        write_json_report(record, report_dir / f"{scan_id}.json")
        return record

    def import_csv_report(self, filename: str, content: bytes) -> ScanRecord:
        scan_id = uuid.uuid4().hex[:12]
        from backend.scanner import import_legacy_csv
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
