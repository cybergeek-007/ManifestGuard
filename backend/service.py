"""ManifestGuard v4 — Scan Service.

Online-only scan orchestration. Local scan and CSV import removed.
Deep scan is always on. Integrates collusion graph, intel burst, and delta cache.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.ai import maybe_enrich_with_ai
from backend.database import database
from backend.models import (
    ExtensionFinding,
    ProfileInstall,
    ScanOptions,
    ScanRecord,
    SuspiciousSignal,
)
from backend.reports import (
    write_csv_report,
    write_html_report,
    write_json_report,
    write_pdf_report,
)

log = logging.getLogger(__name__)


class ScanService:
    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = data_dir or Path(__file__).resolve().parent / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._scans: dict[str, ScanRecord] = {}
        self._lock = threading.Lock()
        self._load_existing_scans()

    def _load_existing_scans(self) -> None:
        """Load scans from SQLite (migrating any legacy JSON reports first)."""
        database.migrate_legacy_reports(self.data_dir)
        for raw in database.load_all_scans():
            try:
                # Stored JSON is nested: { "scan": {...}, "extensions": [...] }
                if "scan" in raw:
                    payload = {**raw["scan"], "extensions": raw.get("extensions", [])}
                else:
                    payload = raw
                scan_id = str(payload.get("scanId", payload.get("scan_id", "")))
                record = ScanRecord.from_dict(payload, self.data_dir / scan_id)
            except Exception:
                continue
            self._scans[record.scan_id] = record

    def _persist_scan(self, record: ScanRecord) -> None:
        """Write-through: register in memory and persist to SQLite."""
        with self._lock:
            self._scans[record.scan_id] = record
        payload = {
            "scan": record.to_summary_dict(),
            "extensions": [finding.to_detail_dict() for finding in record.findings],
        }
        database.save_scan(
            scan_id=record.scan_id,
            created_at=record.created_at.isoformat(),
            status=record.status,
            source=record.source,
            payload=payload,
        )

    # ── Online scan (sole entry point) ────────────────────────

    def create_online_scan(
        self,
        extensions_data: list[dict[str, Any]],
        active_urls: list[str] | None = None,
        enable_ai: bool = False,
        ai_config: dict[str, str] | None = None,
    ) -> ScanRecord:
        """Create a scan from companion extension metadata.

        For each extension:
        1. Check threat intel → check CWS status → fetch reputation
        2. Download CRX from Google → extract → analyze source code (always on)
        3. Run collusion analysis across all extensions
        4. Run intel burst (VirusTotal/OTX/URLScan) on extracted domains
        5. Check delta cache for supply-chain changes
        6. Score using the v4 engine
        7. Generate recommendations for flagged extensions
        """
        from backend.crx_analyzer import cleanup_extraction, download_and_extract
        from backend.intel import lookup_intel
        from backend.recommendations import get_recommendations
        from backend.reputation import compute_reputation_adjustment, fetch_reputation
        from backend.scanner import (
            analyze_codebase,
            choose_verdict,
            compute_reach_score,
            compute_anomaly_score,
            infer_category,
        )
        from backend.store import lookup_store_status

        scan_id = uuid.uuid4().hex  # Full 32 hex chars for enumeration resistance
        findings: list[ExtensionFinding] = []

        # Collect manifests for collusion analysis
        all_manifests: dict[str, dict] = {}
        # Collect extracted JS content for intel burst
        extension_js_content: dict[str, str] = {}
        # Track extraction dirs for cleanup
        extraction_dirs: list[Path] = []
        
        active_urls = active_urls or []

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

            # 5. Reach score (v4: renamed from power_score)
            reach_score = compute_reach_score(permissions, host_permissions)

            # 6. Deep source code analysis (always on in v4)
            signals = []
            timeline = []
            clone_matches: list[dict] = []
            crx_manifest = None
            bg_snippet = ""
            max_obf_str = ""
            if install_type != "development":
                try:
                    crx_result = download_and_extract(ext_id)
                    if crx_result.success and crx_result.extract_dir:
                        crx_manifest = crx_result.manifest or {}
                        all_manifests[ext_id] = crx_manifest

                        # For single-scan flow: update metadata from extracted manifest
                        if name == "Unknown" and crx_manifest:
                            from backend.scanner import resolve_localized_value
                            raw_name = crx_manifest.get("name", "Unknown")
                            name = resolve_localized_value(raw_name, crx_result.extract_dir, crx_manifest.get("default_locale")) or raw_name
                            raw_desc = crx_manifest.get("description", "")
                            description = resolve_localized_value(raw_desc, crx_result.extract_dir, crx_manifest.get("default_locale")) or raw_desc
                            version = crx_manifest.get("version", version)
                            permissions = crx_manifest.get("permissions", permissions)
                            host_permissions = crx_manifest.get("host_permissions", host_permissions)
                            # Re-compute category and reach with real permissions
                            category = infer_category(name, description, permissions)
                            reach_score = compute_reach_score(permissions, host_permissions)

                        signals, timeline, bg_snippet, max_obf_str = analyze_codebase(
                            crx_result.extract_dir, crx_manifest, permissions, host_permissions
                        )
                        # Collect JS content for intel burst
                        js_blobs = []
                        for js_file in crx_result.extract_dir.rglob("*.js"):
                            try:
                                if js_file.stat().st_size > 1_000_000:
                                    continue
                                js_blobs.append(js_file.read_text(encoding="utf-8", errors="ignore"))
                            except Exception:
                                continue
                        extension_js_content[ext_id] = "\n".join(js_blobs)

                        # Delta cache check
                        try:
                            from backend.delta_cache import delta_cache, build_js_structure
                            js_structure = build_js_structure(str(crx_result.extract_dir))
                            delta_result = delta_cache.check_and_record(
                                ext_id, version, b"",  # crx_hash computed internally
                                js_structure
                            )
                        except Exception as e:
                            delta_result = None
                            log.debug("Delta cache error for %s: %s", ext_id, e)

                        # Clone / repackaging detection
                        try:
                            from backend.similarity import (
                                fingerprint_directory, find_clones,
                            )
                            fp = fingerprint_directory(
                                crx_result.extract_dir, ext_id, version, name
                            )
                            if fp is not None:
                                candidates = database.load_all_fingerprints(
                                    exclude_extension_id=ext_id
                                )
                                clone_hits = find_clones(fp, candidates)
                                if clone_hits:
                                    clone_matches = [m.to_dict() for m in clone_hits]
                                    top = clone_hits[0]
                                    signals.append(SuspiciousSignal(
                                        code="repackaged_clone",
                                        title="Possible Repackaged Clone",
                                        severity=20,
                                        detail=(
                                            "Code is a near-duplicate of another "
                                            f"listing: {top.detail}. Repackaged clones "
                                            "of popular extensions are a common malware "
                                            "delivery vector."
                                        ),
                                        evidence=[m.detail for m in clone_hits[:3]],
                                    ))
                                    timeline.append(
                                        f"Clone check: {top.detail}"
                                    )
                                # Record our own fingerprint for future comparisons
                                rec = fp.to_record()
                                database.save_fingerprint(
                                    extension_id=rec["extension_id"],
                                    version=rec["version"],
                                    name=rec["name"],
                                    simhash=rec["simhash"],
                                    file_hashes=rec["file_hashes"],
                                    js_file_count=rec["js_file_count"],
                                    total_js_bytes=rec["total_js_bytes"],
                                )
                        except Exception as e:
                            log.debug("Clone detection error for %s: %s", ext_id, e)

                        extraction_dirs.append(crx_result.extract_dir)
                    else:
                        delta_result = None
                        timeline.append(f"CRX analysis skipped: {crx_result.error}")
                except Exception as e:
                    delta_result = None
                    timeline.append(f"CRX analysis error: {str(e)[:100]}")
            else:
                delta_result = None

            if not timeline:
                timeline.append("Online scan — metadata analysis only.")

            # 7. Behavioral Anomaly score (v4: renamed from suspicion_score)
            raw_anomaly = compute_anomaly_score(
                signals, len(intel_matches), store_status,
                extension_id=ext_id, category=category, permissions=permissions,
            )

            # Apply reputation adjustment
            if reputation_score >= 0:
                adjustment = compute_reputation_adjustment(reputation_score)
                adjusted_anomaly = int(raw_anomaly * adjustment)
            else:
                adjusted_anomaly = raw_anomaly

            # Intel burst: check extracted domains against threat intel APIs
            domain_intel_results = []
            anomaly_boost = 0
            if ext_id in extension_js_content:
                try:
                    from backend.intel_burst import extract_domains_from_code, burst_check_domains_sync, compute_anomaly_boost
                    domains = extract_domains_from_code(extension_js_content[ext_id])
                    if domains:
                        intel_report = burst_check_domains_sync(domains, timeout=2.0)
                        domain_intel_results = intel_report.results
                        anomaly_boost = compute_anomaly_boost(intel_report)
                except Exception as e:
                    log.debug("Intel burst error for %s: %s", ext_id, e)

            # Apply intel burst boost
            adjusted_anomaly = min(adjusted_anomaly + anomaly_boost, 100)

            # Supply-chain delta boost
            if delta_result and delta_result.severity == "critical":
                signals.append(SuspiciousSignal(
                    code="supply_chain_update",
                    title="Silent Supply-Chain Update Detected",
                    severity=25,
                    detail=f"Version {delta_result.new_version} has suspicious structural changes compared to {delta_result.old_version}: "
                           + "; ".join(delta_result.structural_changes[:3]),
                    evidence=delta_result.structural_changes[:5],
                ))
                adjusted_anomaly = min(adjusted_anomaly + 25, 100)
                timeline.append(f"Supply-chain risk: {delta_result.risk_assessment}")

            # Phase 2 AI Integration
            ai_results = {}
            if enable_ai:
                from backend.ai import run_phase2_ai
                ai_results = run_phase2_ai(name, description, bg_snippet, permissions, active_urls, max_obf_str)
                intent = ai_results.get("intent") or {}
                if intent.get("is_deceptive"):
                    signals.append(SuspiciousSignal(
                        code="ai_deceptive_intent",
                        title="AI Intent Classification Warning",
                        severity=25,
                        detail=f"AI classified this as {intent.get('category')} and flagged it as deceptive: {intent.get('reason')}",
                        evidence=["Semantic Intent Classifier (Zero-Shot)"],
                    ))
                    adjusted_anomaly = min(adjusted_anomaly + 25, 100)
                    timeline.append("AI flagged extension description as deceptive compared to code.")

            anomaly_score = min(adjusted_anomaly, 100)

            # 8. Verdict (v4: new ladder)
            verdict, sub_verdict = choose_verdict(
                reach_score, anomaly_score, len(intel_matches),
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
            from backend.models import DomainIntelResult as DomainIntelResultModel
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
                        enabled_state="enabled" if enabled else "disabled",
                        install_source=install_type,
                        version=version,
                        manifest_path="",
                    )
                ],
                reach_score=reach_score,
                anomaly_score=anomaly_score,
                verdict=verdict,
                sub_verdict=sub_verdict,
                store_status=store_status,
                suspicious_signals=signals,
                intel_matches=intel_matches,
                evidence_timeline=timeline,
                homepage_url=ext.get("homepageUrl"),
                category=category,
                reputation_score=reputation_score,
                reputation_details=reputation_details,
                adjusted_anomaly_score=anomaly_score,
                recommendations=recommendations,
                domain_intel=[
                    DomainIntelResultModel(
                        domain=r.domain, source=r.source,
                        is_malicious=r.is_malicious, confidence=r.confidence,
                        detail=r.detail, last_checked=r.last_checked,
                    ) for r in domain_intel_results
                ] if domain_intel_results else [],
                version_delta=delta_result,
                intent_classification=ai_results.get("intent"),
                attack_simulation=ai_results.get("attack"),
                deobfuscated_payload=ai_results.get("deobfuscated"),
                clone_matches=clone_matches,
            )
            findings.append(finding)

        # ── Cross-extension collusion analysis ────────────────
        try:
            from backend.collusion import analyze_collusion
            collusion_report = analyze_collusion(extensions_data, all_manifests)
            # Attach collusion edges to affected findings
            for finding in findings:
                finding.collusion_edges = [
                    edge for edge in collusion_report.edges
                    if edge.source_id == finding.id or edge.target_id == finding.id
                ]
        except Exception as e:
            log.debug("Collusion analysis error: %s", e)

        # Cleanup all extraction directories
        for extract_dir in extraction_dirs:
            cleanup_extraction(extract_dir)

        # Enrich with AI if requested
        maybe_enrich_with_ai(findings, enable_ai, ai_config=ai_config)

        # Sort by risk
        findings.sort(
            key=lambda f: (
                f.verdict != "known_malicious",
                -f.anomaly_score,
                -f.reach_score,
                f.name.lower(),
            )
        )

        record = ScanRecord(
            scan_id=scan_id,
            created_at=datetime.now(timezone.utc),
            status="completed",
            source="online_scan",
            options=ScanOptions(enable_live_checks=True, enable_ai=enable_ai),
            findings=findings,
            report_dir=self.data_dir / scan_id,
        )
        self._persist_scan(record)
        return record

    # ── Local OS scan (Windows only) ──────────────────────────

    def create_local_scan(self, enable_ai: bool = False, ai_config: dict[str, str] | None = None) -> ScanRecord:
        """Fast local scan: reads extension files directly from disk.

        Key optimisations vs. the online pipeline:
        - Reads the already-extracted manifest / JS directly (no CRX download).
        - Runs each extension in a ThreadPoolExecutor (8 workers).
        - Skips intel burst (URLScan/OTX/VT) to keep latency low.
        - Hard cap of 50 extensions to prevent runaway scans.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout

        from backend.intel import lookup_intel
        from backend.models import ExtensionFinding, ProfileInstall, ScanOptions, SuspiciousSignal
        from backend.reputation import compute_reputation_adjustment, fetch_reputation
        from backend.scanner import (
            analyze_codebase,
            choose_verdict,
            compute_anomaly_score,
            compute_reach_score,
            infer_category,
        )
        from backend.store import lookup_store_status

        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise ValueError("LOCALAPPDATA not found. This feature only works on Windows.")

        chrome_user_data = Path(local_app_data) / "Google" / "Chrome" / "User Data"
        if not chrome_user_data.exists():
            raise ValueError("Chrome User Data not found. Make sure Chrome is installed.")

        # ── 1. Discover local extensions ─────────────────────
        ext_dirs: dict[str, Path] = {}  # id -> version dir (deduplicated)
        profiles = ["Default"] + [d.name for d in chrome_user_data.glob("Profile *") if d.is_dir()]

        for profile in profiles:
            ext_base = chrome_user_data / profile / "Extensions"
            if not ext_base.exists():
                continue
            for ext_id_path in ext_base.iterdir():
                if not ext_id_path.is_dir() or len(ext_id_path.name) != 32:
                    continue
                if ext_id_path.name in ext_dirs:
                    continue  # already have this extension from another profile
                versions = [d for d in ext_id_path.iterdir() if d.is_dir()]
                if not versions:
                    continue
                latest = sorted(versions, key=lambda x: x.name)[-1]
                if (latest / "manifest.json").exists():
                    ext_dirs[ext_id_path.name] = latest

        if not ext_dirs:
            raise ValueError("No installed Chrome extensions found on this machine.")

        # Cap at 50 to keep scan time reasonable
        MAX_EXTENSIONS = 50
        all_ids = list(ext_dirs.keys())[:MAX_EXTENSIONS]
        log.info("Local scan: found %d extensions (capped at %d)", len(ext_dirs), MAX_EXTENSIONS)

        # ── 2. Per-extension worker ────────────────────────────
        def scan_one(ext_id: str) -> ExtensionFinding | None:
            version_dir = ext_dirs[ext_id]
            try:
                manifest = json.loads((version_dir / "manifest.json").read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                return None

            name = manifest.get("name", "Unknown")
            # Strip Chrome i18n placeholder e.g. __MSG_appName__
            if name.startswith("__MSG_"):
                name = manifest.get("short_name", name.replace("__MSG_", "").replace("__", "").replace("_", " ").title())
            version = manifest.get("version", "unknown")
            description = manifest.get("description", "")
            if description.startswith("__MSG_"):
                description = ""
            permissions = manifest.get("permissions", [])
            host_permissions = manifest.get("host_permissions", [])

            # Skip Chrome internal extensions
            if name in ("Chrome", "Chromium") or ext_id.startswith("nmmhkkegcc"):
                return None

            # Fast checks (no network)
            intel_matches = lookup_intel(ext_id)
            store_status = lookup_store_status(ext_id).status
            category = infer_category(name, description, permissions)
            reach_score = compute_reach_score(permissions, host_permissions)

            # Reputation (network — fast, uses cache)
            reputation_score = -1
            reputation_details = None
            try:
                rep = fetch_reputation(ext_id)
                if rep.lookup_status == "success":
                    reputation_score = rep.reputation_score
                    reputation_details = rep.to_dict()
            except Exception:
                pass

            # Local JS analysis — read directly from disk, no download needed
            signals: list[SuspiciousSignal] = []
            timeline: list[str] = ["Local scan — reading extension files from disk."]
            try:
                signals, timeline_extra, _, _ = analyze_codebase(
                    version_dir, manifest, permissions, host_permissions
                )
                timeline += timeline_extra
            except Exception as e:
                timeline.append(f"Code analysis error: {str(e)[:80]}")

            # Anomaly score
            raw_anomaly = compute_anomaly_score(
                signals, len(intel_matches), store_status,
                extension_id=ext_id, category=category, permissions=permissions,
            )
            if reputation_score >= 0:
                from backend.reputation import compute_reputation_adjustment
                raw_anomaly = int(raw_anomaly * compute_reputation_adjustment(reputation_score))
            anomaly_score = min(raw_anomaly, 100)

            verdict, sub_verdict = choose_verdict(
                reach_score, anomaly_score, len(intel_matches),
                store_status, extension_id=ext_id, reputation_score=reputation_score,
            )

            # Recommendations for flagged extensions
            recommendations: list[dict] = []
            if verdict in ("suspicious", "moderate_risk", "known_malicious"):
                try:
                    from backend.recommendations import get_recommendations
                    recs = get_recommendations(name, description, category)
                    recommendations = [r.to_dict() for r in recs]
                except Exception:
                    pass

            return ExtensionFinding(
                id=ext_id,
                name=name,
                version=version,
                description=description,
                manifest_version=manifest.get("manifest_version", 2),
                permissions=permissions,
                optional_permissions=[],
                host_permissions=host_permissions,
                optional_host_permissions=[],
                content_script_matches=[],
                profiles=[
                    ProfileInstall(
                        profile_id="local",
                        profile_name="Local Chrome",
                        browser_channel="stable",
                        browser_family="chromium",
                        enabled_state="enabled",
                        install_source="local",
                        version=version,
                        manifest_path=str(version_dir / "manifest.json"),
                    )
                ],
                reach_score=reach_score,
                anomaly_score=anomaly_score,
                verdict=verdict,
                sub_verdict=sub_verdict,
                store_status=store_status,
                suspicious_signals=signals,
                intel_matches=intel_matches,
                evidence_timeline=timeline,
                homepage_url=manifest.get("homepage_url", ""),
                category=category,
                reputation_score=reputation_score,
                reputation_details=reputation_details,
                adjusted_anomaly_score=anomaly_score,
                recommendations=recommendations,
                domain_intel=[],
                version_delta=None,
                intent_classification=None,
                attack_simulation=None,
                deobfuscated_payload=None,
            )

        # ── 3. Run in parallel ─────────────────────────────────
        findings: list[ExtensionFinding] = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(scan_one, eid): eid for eid in all_ids}
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=30)
                    if result is not None:
                        findings.append(result)
                except FuturesTimeout:
                    log.warning("Extension %s timed out during local scan", futures[future])
                except Exception as e:
                    log.warning("Extension %s failed: %s", futures[future], e)

        if not findings:
            raise ValueError("No extensions could be analyzed.")

        # Sort by risk
        findings.sort(key=lambda f: (
            f.verdict != "known_malicious",
            -f.anomaly_score,
            -f.reach_score,
            f.name.lower(),
        ))

        # AI enrichment (generate summaries if enabled)
        maybe_enrich_with_ai(findings, enable_ai, ai_config=ai_config)

        # ── 4. Save and return ─────────────────────────────────
        scan_id = uuid.uuid4().hex  # Full 32 hex chars for enumeration resistance
        record = ScanRecord(
            scan_id=scan_id,
            created_at=datetime.now(timezone.utc),
            status="completed",
            source="local_scan",
            options=ScanOptions(enable_live_checks=True, enable_ai=enable_ai),
            findings=findings,
            report_dir=self.data_dir / scan_id,
        )
        self._persist_scan(record)
        log.info("Local scan complete: %d extensions in scan %s", len(findings), scan_id)
        return record


    # ── Single extension scan ─────────────────────────────

    def create_single_extension_scan(
        self,
        extension_id: str,
        enable_ai: bool = False,
        ai_config: dict[str, str] | None = None,
    ) -> dict:
        """Scan a single extension by Chrome Web Store ID.

        Validates the ID format, constructs a minimal extension dict, and
        delegates to create_online_scan() which handles CRX download,
        manifest extraction, and the full analysis pipeline.
        """
        import re

        # Validate extension ID format: 32 lowercase a-p characters
        if not re.fullmatch(r"[a-p]{32}", extension_id):
            return {"error": "Invalid extension ID format. Must be 32 lowercase a-p characters."}

        ext_data = {
            "id": extension_id,
            "name": "Unknown",  # Will be updated during CRX analysis
            "version": "0.0.0",
            "description": "",
            "permissions": [],
            "hostPermissions": [],
            "enabled": True,
            "installType": "normal",
        }

        record = self.create_online_scan(
            [ext_data],
            active_urls=[],
            enable_ai=enable_ai,
            ai_config=ai_config,
        )
        return record.to_summary_dict()

    # ── Read operations ───────────────────────────────────

    def list_scans(self) -> list[ScanRecord]:
        with self._lock:
            scans = list(self._scans.values())
        return sorted(scans, key=lambda scan: scan.created_at, reverse=True)

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        with self._lock:
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
        scan.report_dir.mkdir(parents=True, exist_ok=True)
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

    # ── Watchlist / continuous monitoring ─────────────────

    def watchlist_add(self, extension_id: str) -> dict:
        """Add an extension to the monitoring watchlist.

        Runs an initial scan to capture a baseline (version, verdict,
        permissions, contacted domains) so future re-checks can diff
        against it.
        """
        finding = self._scan_single_finding(extension_id)
        if finding is None:
            return {"error": "Could not analyze extension for monitoring"}
        database.watchlist_add(
            extension_id=extension_id,
            name=finding.name,
            version=finding.version,
            verdict=finding.verdict,
        )
        # Seed baseline state so the first re-check has something to diff.
        self._save_watch_baseline(finding)
        return {"status": "added", "extensionId": extension_id, "name": finding.name}

    def watchlist_remove(self, extension_id: str) -> dict:
        removed = database.watchlist_remove(extension_id)
        return {"status": "removed" if removed else "not_found", "extensionId": extension_id}

    def watchlist_all(self) -> list[dict]:
        return database.watchlist_all()

    def watchlist_check(self, extension_id: str) -> dict:
        """Re-analyze a watched extension and record any behavioral drift."""
        entries = {e["extensionId"]: e for e in database.watchlist_all()}
        prev = entries.get(extension_id)
        if prev is None:
            return {"error": "Extension is not on the watchlist"}

        finding = self._scan_single_finding(extension_id)
        if finding is None:
            return {"error": "Re-scan failed"}

        alerts = self._diff_watch_state(prev, finding)
        database.watchlist_update(
            extension_id=extension_id,
            version=finding.version,
            verdict=finding.verdict,
            new_alerts=alerts,
        )
        self._save_watch_baseline(finding)
        return {
            "extensionId": extension_id,
            "name": finding.name,
            "version": finding.version,
            "verdict": finding.verdict,
            "newAlerts": alerts,
        }

    def watchlist_check_all(self) -> list[dict]:
        results = []
        for entry in database.watchlist_all():
            results.append(self.watchlist_check(entry["extensionId"]))
        return results

    def _scan_single_finding(self, extension_id: str) -> ExtensionFinding | None:
        """Run the full online pipeline for one extension, return its finding."""
        ext_data = {
            "id": extension_id,
            "name": "Unknown",
            "version": "",
            "description": "",
            "permissions": [],
            "hostPermissions": [],
            "enabled": True,
            "installType": "normal",
        }
        record = self.create_online_scan([ext_data], active_urls=[], enable_ai=False)
        return record.findings[0] if record.findings else None

    def _domains_of(self, finding: ExtensionFinding) -> set[str]:
        return {d.domain for d in finding.domain_intel if getattr(d, "domain", None)}

    def _save_watch_baseline(self, finding: ExtensionFinding) -> None:
        """Persist the current permissions/domains snapshot for diffing."""
        database.watchlist_set_baseline(
            extension_id=finding.id,
            permissions=sorted(set(finding.permissions) | set(finding.host_permissions)),
            domains=sorted(self._domains_of(finding)),
            has_obfuscation=any(
                s.code in ("obfuscation", "heavy_obfuscation")
                for s in finding.suspicious_signals
            ),
        )

    def _diff_watch_state(self, prev: dict, finding: ExtensionFinding) -> list[dict]:
        """Compare a re-scan to the stored baseline and emit alert dicts."""
        alerts: list[dict] = []
        now = datetime.now(timezone.utc).isoformat()
        baseline = database.watchlist_get_baseline(finding.id)

        # Version change
        prev_version = prev.get("lastVersion")
        if prev_version and finding.version and finding.version != prev_version:
            alerts.append({
                "type": "version_change",
                "severity": "info",
                "message": f"Updated from v{prev_version} to v{finding.version}",
                "at": now,
            })

        # Verdict escalation
        order = ["safe", "low_risk", "moderate_risk", "suspicious", "known_malicious"]
        prev_verdict = prev.get("lastVerdict") or "safe"
        try:
            if order.index(finding.verdict) > order.index(prev_verdict):
                alerts.append({
                    "type": "verdict_escalation",
                    "severity": "high",
                    "message": f"Risk verdict escalated: {prev_verdict} -> {finding.verdict}",
                    "at": now,
                })
        except ValueError:
            pass

        if baseline:
            # New permissions
            new_perms = sorted(
                (set(finding.permissions) | set(finding.host_permissions))
                - set(baseline.get("permissions", []))
            )
            if new_perms:
                alerts.append({
                    "type": "new_permissions",
                    "severity": "high",
                    "message": "New permissions requested: " + ", ".join(new_perms[:6]),
                    "at": now,
                })
            # New contacted domains
            new_domains = sorted(self._domains_of(finding) - set(baseline.get("domains", [])))
            if new_domains:
                alerts.append({
                    "type": "new_domains",
                    "severity": "medium",
                    "message": "New network domains contacted: " + ", ".join(new_domains[:6]),
                    "at": now,
                })
            # Obfuscation appeared
            if not baseline.get("has_obfuscation") and any(
                s.code in ("obfuscation", "heavy_obfuscation")
                for s in finding.suspicious_signals
            ):
                alerts.append({
                    "type": "obfuscation_introduced",
                    "severity": "high",
                    "message": "Code obfuscation newly detected in this version",
                    "at": now,
                })
        return alerts


service = ScanService()
