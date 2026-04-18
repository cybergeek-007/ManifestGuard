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
    power_score: int
    suspicion_score: int
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

    def to_inventory_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "profiles": [profile.to_dict() for profile in self.profiles],
            "enabledState": self.primary_enabled_state,
            "installSource": self.primary_install_source,
            "powerScore": self.power_score,
            "suspicionScore": self.suspicion_score,
            "verdict": self.verdict,
            "storeStatus": self.store_status,
            "permissions": self.permissions,
            "hostPermissions": self.host_permissions,
            "suspiciousSignals": [signal.to_dict() for signal in self.suspicious_signals],
            "intelMatches": [match.to_dict() for match in self.intel_matches],
            "aiSummary": self.ai_summary,
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
            }
        )
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ExtensionFinding":
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
            power_score=int(payload.get("powerScore", payload.get("power_score", 0))),
            suspicion_score=int(payload.get("suspicionScore", payload.get("suspicion_score", 0))),
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
        )

    @property
    def primary_enabled_state(self) -> str:
        return self.profiles[0].enabled_state if self.profiles else "unknown"

    @property
    def primary_install_source(self) -> str:
        return self.profiles[0].install_source if self.profiles else "unknown"


@dataclass(slots=True)
class ScanOptions:
    profiles: list[str] | None = None
    channels: list[str] | None = None
    enable_live_checks: bool = False
    enable_ai: bool = False
    roots: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "profiles": self.profiles or [],
            "channels": self.channels or [],
            "enableLiveChecks": self.enable_live_checks,
            "enableAi": self.enable_ai,
            "roots": self.roots or [],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScanOptions":
        return cls(
            profiles=[str(item) for item in payload.get("profiles", [])] or None,
            channels=[str(item) for item in payload.get("channels", [])] or None,
            enable_live_checks=bool(payload.get("enableLiveChecks", payload.get("enable_live_checks", False))),
            enable_ai=bool(payload.get("enableAi", payload.get("enable_ai", False))),
            roots=[str(item) for item in payload.get("roots", [])] or None,
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
        profiles = set()
        channels = set()
        for finding in self.findings:
            verdicts[finding.verdict] = verdicts.get(finding.verdict, 0) + 1
            for profile in finding.profiles:
                profiles.add(profile.profile_name)
                channels.add(profile.browser_channel)
        return {
            "totalExtensions": len(self.findings),
            "verdictDistribution": verdicts,
            "profilesScanned": sorted(profiles),
            "channelsScanned": sorted(channels),
        }

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "scanId": self.scan_id,
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
            source=str(payload.get("source", "local_scan")),
            options=ScanOptions.from_dict(payload.get("options", {})),
            findings=[ExtensionFinding.from_dict(item) for item in extensions],
            report_dir=report_dir,
        )
