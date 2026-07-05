from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class SuspiciousSignal:
    code: str
    title: str
    severity: int
    detail: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SuspiciousSignal":
        return cls(
            code=str(payload.get("code", "")),
            title=str(payload.get("title", "")),
            severity=int(payload.get("severity", 0)),
            detail=str(payload.get("detail", "")),
            evidence=[str(item) for item in payload.get("evidence", [])],
        )


@dataclass(slots=True)
class IntelMatch:
    extension_id: str
    label: str
    source: str
    source_url: str
    confidence: str
    detail: str
    category: str = "known_bad"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "IntelMatch":
        return cls(
            extension_id=str(payload.get("extension_id", payload.get("extensionId", ""))),
            label=str(payload.get("label", "")),
            source=str(payload.get("source", "")),
            source_url=str(payload.get("source_url", payload.get("sourceUrl", ""))),
            confidence=str(payload.get("confidence", "")),
            detail=str(payload.get("detail", "")),
            category=str(payload.get("category", "known_bad")),
        )


@dataclass(slots=True)
class ProfileInstall:
    profile_id: str
    profile_name: str
    browser_channel: str
    browser_family: str
    enabled_state: str
    install_source: str
    version: str
    manifest_path: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ProfileInstall":
        return cls(
            profile_id=str(payload.get("profile_id", payload.get("profileId", ""))),
            profile_name=str(payload.get("profile_name", payload.get("profileName", ""))),
            browser_channel=str(payload.get("browser_channel", payload.get("browserChannel", ""))),
            browser_family=str(payload.get("browser_family", payload.get("browserFamily", ""))),
            enabled_state=str(payload.get("enabled_state", payload.get("enabledState", "unknown"))),
            install_source=str(payload.get("install_source", payload.get("installSource", "unknown"))),
            version=str(payload.get("version", "unknown")),
            manifest_path=str(payload.get("manifest_path", payload.get("manifestPath", ""))),
        )


# ── Phase 1 new data classes ──────────────────────────────────


@dataclass(slots=True)
class CollusionEdge:
    """A collusion risk between two co-installed extensions."""

    source_id: str
    source_name: str
    target_id: str
    target_name: str
    risk_type: str          # externally_connectable | shared_domain | permission_chain | web_accessible_abuse
    detail: str
    severity: str           # high | medium | low

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CollusionEdge":
        return cls(
            source_id=str(payload.get("source_id", payload.get("sourceId", ""))),
            source_name=str(payload.get("source_name", payload.get("sourceName", ""))),
            target_id=str(payload.get("target_id", payload.get("targetId", ""))),
            target_name=str(payload.get("target_name", payload.get("targetName", ""))),
            risk_type=str(payload.get("risk_type", payload.get("riskType", ""))),
            detail=str(payload.get("detail", "")),
            severity=str(payload.get("severity", "low")),
        )


@dataclass(slots=True)
class DomainIntelResult:
    """Result from an external threat intelligence API check."""

    domain: str
    source: str             # virustotal | alienvault_otx | urlscan
    is_malicious: bool
    confidence: float       # 0.0 – 1.0
    detail: str
    last_checked: str       # ISO-8601

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DomainIntelResult":
        return cls(
            domain=str(payload.get("domain", "")),
            source=str(payload.get("source", "")),
            is_malicious=bool(payload.get("is_malicious", payload.get("isMalicious", False))),
            confidence=float(payload.get("confidence", 0.0)),
            detail=str(payload.get("detail", "")),
            last_checked=str(payload.get("last_checked", payload.get("lastChecked", ""))),
        )


@dataclass(slots=True)
class DeltaResult:
    """Structural diff between two versions of the same extension."""

    extension_id: str
    old_version: str
    new_version: str
    structural_changes: list[str]       # Human-readable change descriptions
    risk_assessment: str                # supply_chain_risk | significant_update | normal_update | minor_patch
    new_eval_count_delta: int
    new_obfuscated_delta: int
    severity: str                       # critical | warning | info

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DeltaResult":
        return cls(
            extension_id=str(payload.get("extension_id", payload.get("extensionId", ""))),
            old_version=str(payload.get("old_version", payload.get("oldVersion", ""))),
            new_version=str(payload.get("new_version", payload.get("newVersion", ""))),
            structural_changes=list(payload.get("structural_changes", payload.get("structuralChanges", []))),
            risk_assessment=str(payload.get("risk_assessment", payload.get("riskAssessment", "normal_update"))),
            new_eval_count_delta=int(payload.get("new_eval_count_delta", payload.get("newEvalCountDelta", 0))),
            new_obfuscated_delta=int(payload.get("new_obfuscated_delta", payload.get("newObfuscatedDelta", 0))),
            severity=str(payload.get("severity", "info")),
        )


# ── Core finding model ──────────────────────────────────


@dataclass(slots=True)
class ExtensionFinding:
    id: str
    name: str
    version: str
    description: str
    manifest_version: int
    permissions: list[str]
    optional_permissions: list[str]
    host_permissions: list[str]
    optional_host_permissions: list[str]
    content_script_matches: list[str]
    profiles: list[ProfileInstall]
    reach_score: int                    # v4: renamed from power_score
    anomaly_score: int                  # v4: renamed from suspicion_score
    verdict: str
    store_status: str
    suspicious_signals: list[SuspiciousSignal] = field(default_factory=list)
    intel_matches: list[IntelMatch] = field(default_factory=list)
    ai_summary: str | None = None
    evidence_timeline: list[str] = field(default_factory=list)
    package_root: str | None = None
    homepage_url: str | None = None
    author: str | None = None
    last_analyzed_at: str = field(default_factory=lambda: utcnow().isoformat())
    # v3 fields
    category: str | None = None
    reputation_score: int = -1
    reputation_details: dict[str, Any] | None = None
    adjusted_anomaly_score: int = 0     # v4: renamed from adjusted_suspicion_score
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    # v4 Phase 1 fields
    collusion_edges: list[CollusionEdge] = field(default_factory=list)
    domain_intel: list[DomainIntelResult] = field(default_factory=list)
    version_delta: DeltaResult | None = None
    sub_verdict: str | None = None      # "Threat Intel Match", "CWS Removed", "High Reach, Verified", etc.
    # v4 Phase 2 fields
    intent_classification: dict[str, Any] | None = None
    attack_simulation: str | None = None
    deobfuscated_payload: str | None = None
    # v5 field: repackaged-clone detection matches
    clone_matches: list[dict[str, Any]] = field(default_factory=list)

    def to_inventory_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "profiles": [profile.to_dict() for profile in self.profiles],
            "enabledState": self.primary_enabled_state,
            "installSource": self.primary_install_source,
            "reachScore": self.reach_score,
            "anomalyScore": self.anomaly_score,
            "verdict": self.verdict,
            "subVerdict": self.sub_verdict,
            "storeStatus": self.store_status,
            "permissions": self.permissions,
            "hostPermissions": self.host_permissions,
            "suspiciousSignals": [signal.to_dict() for signal in self.suspicious_signals],
            "intelMatches": [match.to_dict() for match in self.intel_matches],
            "aiSummary": self.ai_summary,
            "category": self.category,
            "reputationScore": self.reputation_score,
            "adjustedAnomalyScore": self.adjusted_anomaly_score,
            "recommendations": self.recommendations,
            "collusionEdges": [edge.to_dict() for edge in self.collusion_edges],
            "domainIntel": [result.to_dict() for result in self.domain_intel],
            "versionDelta": self.version_delta.to_dict() if self.version_delta else None,
            "intentClassification": self.intent_classification,
            "attackSimulation": self.attack_simulation,
            "deobfuscatedPayload": self.deobfuscated_payload,
            "cloneMatches": self.clone_matches,
        }

    def to_detail_dict(self) -> dict[str, Any]:
        payload = self.to_inventory_dict()
        payload.update(
            {
                "description": self.description,
                "manifestVersion": self.manifest_version,
                "optionalPermissions": self.optional_permissions,
                "optionalHostPermissions": self.optional_host_permissions,
                "contentScriptMatches": self.content_script_matches,
                "evidenceTimeline": self.evidence_timeline,
                "packageRoot": self.package_root,
                "homepageUrl": self.homepage_url,
                "author": self.author,
                "lastAnalyzedAt": self.last_analyzed_at,
                "reputationDetails": self.reputation_details,
            }
        )
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ExtensionFinding":
        # v4 backward compat: accept old powerScore/suspicionScore names
        reach = int(payload.get("reachScore", payload.get("reach_score",
                     payload.get("powerScore", payload.get("power_score", 0)))))
        anomaly = int(payload.get("anomalyScore", payload.get("anomaly_score",
                      payload.get("suspicionScore", payload.get("suspicion_score", 0)))))
        adjusted = int(payload.get("adjustedAnomalyScore", payload.get("adjusted_anomaly_score",
                       payload.get("adjustedSuspicionScore", payload.get("adjusted_suspicion_score", 0)))))

        # Parse v4 phase 1 fields
        collusion_raw = payload.get("collusionEdges", payload.get("collusion_edges", []))
        domain_intel_raw = payload.get("domainIntel", payload.get("domain_intel", []))
        delta_raw = payload.get("versionDelta", payload.get("version_delta"))

        return cls(
            id=str(payload.get("id", "")),
            name=str(payload.get("name", "Unknown Extension")),
            version=str(payload.get("version", "unknown")),
            description=str(payload.get("description", "")),
            manifest_version=int(payload.get("manifestVersion", payload.get("manifest_version", 0))),
            permissions=[str(item) for item in payload.get("permissions", [])],
            optional_permissions=[str(item) for item in payload.get("optionalPermissions", payload.get("optional_permissions", []))],
            host_permissions=[str(item) for item in payload.get("hostPermissions", payload.get("host_permissions", []))],
            optional_host_permissions=[
                str(item) for item in payload.get("optionalHostPermissions", payload.get("optional_host_permissions", []))
            ],
            content_script_matches=[
                str(item) for item in payload.get("contentScriptMatches", payload.get("content_script_matches", []))
            ],
            profiles=[ProfileInstall.from_dict(item) for item in payload.get("profiles", [])],
            reach_score=reach,
            anomaly_score=anomaly,
            verdict=str(payload.get("verdict", "unknown")),
            store_status=str(payload.get("storeStatus", payload.get("store_status", "unknown"))),
            suspicious_signals=[SuspiciousSignal.from_dict(item) for item in payload.get("suspiciousSignals", payload.get("suspicious_signals", []))],
            intel_matches=[IntelMatch.from_dict(item) for item in payload.get("intelMatches", payload.get("intel_matches", []))],
            ai_summary=payload.get("aiSummary", payload.get("ai_summary")),
            evidence_timeline=[str(item) for item in payload.get("evidenceTimeline", payload.get("evidence_timeline", []))],
            package_root=payload.get("packageRoot", payload.get("package_root")),
            homepage_url=payload.get("homepageUrl", payload.get("homepage_url")),
            author=payload.get("author"),
            last_analyzed_at=str(payload.get("lastAnalyzedAt", payload.get("last_analyzed_at", utcnow().isoformat()))),
            category=payload.get("category"),
            reputation_score=int(payload.get("reputationScore", payload.get("reputation_score", -1))),
            reputation_details=payload.get("reputationDetails", payload.get("reputation_details")),
            adjusted_anomaly_score=adjusted,
            recommendations=list(payload.get("recommendations", [])),
            collusion_edges=[CollusionEdge.from_dict(e) for e in collusion_raw],
            domain_intel=[DomainIntelResult.from_dict(d) for d in domain_intel_raw],
            version_delta=DeltaResult.from_dict(delta_raw) if delta_raw else None,
            sub_verdict=payload.get("subVerdict", payload.get("sub_verdict")),
            intent_classification=payload.get("intentClassification", payload.get("intent_classification")),
            attack_simulation=payload.get("attackSimulation", payload.get("attack_simulation")),
            deobfuscated_payload=payload.get("deobfuscatedPayload", payload.get("deobfuscated_payload")),
            clone_matches=list(payload.get("cloneMatches", payload.get("clone_matches", []))),
        )

    @property
    def primary_enabled_state(self) -> str:
        return self.profiles[0].enabled_state if self.profiles else "unknown"

    @property
    def primary_install_source(self) -> str:
        return self.profiles[0].install_source if self.profiles else "unknown"


@dataclass(slots=True)
class ScanOptions:
    enable_live_checks: bool = False
    enable_ai: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "enableLiveChecks": self.enable_live_checks,
            "enableAi": self.enable_ai,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScanOptions":
        return cls(
            enable_live_checks=bool(payload.get("enableLiveChecks", payload.get("enable_live_checks", False))),
            enable_ai=bool(payload.get("enableAi", payload.get("enable_ai", False))),
        )


@dataclass(slots=True)
class ScanRecord:
    scan_id: str
    created_at: datetime
    status: str
    source: str
    options: ScanOptions
    findings: list[ExtensionFinding]
    report_dir: Path

    def summary(self) -> dict[str, Any]:
        verdicts: dict[str, int] = {}
        for finding in self.findings:
            verdicts[finding.verdict] = verdicts.get(finding.verdict, 0) + 1
        return {
            "totalExtensions": len(self.findings),
            "verdictDistribution": verdicts,
        }

    def _build_label(self) -> str:
        """Generate a human-readable name for this scan."""
        summary = self.summary()
        parts: list[str] = []
        parts.append(self.source.replace("_", " ").title())

        # Extension count
        count = summary["totalExtensions"]
        parts.append(f"{count} extension{'s' if count != 1 else ''}")

        return " \u00b7 ".join(parts)

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "scanId": self.scan_id,
            "label": self._build_label(),
            "createdAt": self.created_at.isoformat(),
            "status": self.status,
            "source": self.source,
            "options": self.options.to_dict(),
            "summary": self.summary(),
        }

    def to_detail_dict(self) -> dict[str, Any]:
        payload = self.to_summary_dict()
        payload["extensions"] = [finding.to_inventory_dict() for finding in self.findings]
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any], report_dir: Path) -> "ScanRecord":
        extensions = payload.get("extensions", [])
        return cls(
            scan_id=str(payload.get("scanId", payload.get("scan_id", report_dir.name))),
            created_at=datetime.fromisoformat(str(payload.get("createdAt", payload.get("created_at", utcnow().isoformat())))),
            status=str(payload.get("status", "completed")),
            source=str(payload.get("source", "online_scan")),
            options=ScanOptions.from_dict(payload.get("options", {})),
            findings=[ExtensionFinding.from_dict(item) for item in extensions],
            report_dir=report_dir,
        )
