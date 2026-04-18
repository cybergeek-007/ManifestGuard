from __future__ import annotations

import csv
import json
import os
import platform
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from backend.intel import lookup_intel
from backend.models import ExtensionFinding, ProfileInstall, ScanOptions, SuspiciousSignal
from backend.store import lookup_store_status

POWER_WEIGHTS = {
    "<all_urls>": 40,
    "all_urls": 40,
    "*://*/*": 40,
    "webRequestBlocking": 30,
    "debugger": 30,
    "proxy": 25,
    "cookies": 20,
    "webRequest": 18,
    "declarativeNetRequest": 15,
    "history": 15,
    "management": 15,
    "tabs": 12,
    "activeTab": 10,
    "downloads": 10,
    "clipboardRead": 8,
    "clipboardWrite": 8,
    "scripting": 6,
}

NARROW_PURPOSE_KEYWORDS = {
    "theme",
    "dark mode",
    "emoji",
    "wallpaper",
    "new tab",
    "color picker",
    "screenshot",
    "video downloader",
    "refresh",
    "calculator",
    "notes",
}

STATE_LABELS = {
    0: "disabled",
    1: "enabled",
    2: "disabled",
    3: "terminated",
    4: "blacklisted",
}

LOCATION_LABELS = {
    0: "unknown",
    1: "web_store",
    2: "external_pref",
    3: "external_registry",
    4: "unpacked",
    5: "component",
    8: "external_policy",
    9: "command_line",
    10: "external_policy_download",
}


@dataclass(slots=True)
class RawInstall:
    extension_id: str
    profile_install: ProfileInstall
    info: dict[str, Any]
    suspicious_signals: list[SuspiciousSignal]
    power_score: int
    suspicion_score: int
    evidence_timeline: list[str]


def discover_channel_roots(override_roots: list[str] | None = None) -> list[tuple[str, str, Path]]:
    if override_roots:
        return [("custom", "override", Path(root)) for root in override_roots]

    home = Path.home()
    local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
    system = platform.system().lower()

    if system.startswith("win"):
        return [
            ("chrome", "stable", local / "Google" / "Chrome" / "User Data"),
            ("chrome", "beta", local / "Google" / "Chrome Beta" / "User Data"),
            ("chrome", "dev", local / "Google" / "Chrome Dev" / "User Data"),
            ("chromium", "stable", local / "Chromium" / "User Data"),
        ]
    if system == "darwin":
        app_support = home / "Library" / "Application Support"
        return [
            ("chrome", "stable", app_support / "Google" / "Chrome"),
            ("chrome", "beta", app_support / "Google" / "Chrome Beta"),
            ("chromium", "stable", app_support / "Chromium"),
        ]
    return [
        ("chrome", "stable", home / ".config" / "google-chrome"),
        ("chrome", "beta", home / ".config" / "google-chrome-beta"),
        ("chromium", "stable", home / ".config" / "chromium"),
    ]


def discover_profiles(root: Path, include_profiles: list[str] | None = None) -> list[Path]:
    if not root.exists():
        return []

    candidates = []
    for path in root.iterdir():
        if not path.is_dir():
            continue
        if path.name == "Default" or path.name.startswith("Profile "):
            candidates.append(path)
    if include_profiles:
        include = set(include_profiles)
        candidates = [path for path in candidates if path.name in include]
    return sorted(candidates, key=lambda item: (item.name != "Default", item.name))


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_profile_names(root: Path) -> dict[str, str]:
    local_state = read_json(root / "Local State") or {}
    info_cache = local_state.get("profile", {}).get("info_cache", {})
    names: dict[str, str] = {}
    if isinstance(info_cache, dict):
        for profile_id, data in info_cache.items():
            if isinstance(data, dict):
                names[profile_id] = str(data.get("name") or profile_id)
    return names


def parse_message_key(value: str) -> str | None:
    match = re.fullmatch(r"__MSG_([A-Za-z0-9_@]+)__", value.strip())
    return match.group(1).lower() if match else None


def resolve_localized_value(value: str, manifest_dir: Path, default_locale: str | None) -> str:
    key = parse_message_key(value)
    if not key:
        return value

    locale_candidates = []
    if default_locale:
        locale_candidates.append(default_locale)
    locale_candidates.extend(["en", "en_US"])

    locale_dir = manifest_dir / "_locales"
    checked: set[str] = set()
    for locale in locale_candidates:
        if not locale or locale in checked:
            continue
        checked.add(locale)
        messages = read_json(locale_dir / locale / "messages.json")
        if not isinstance(messages, dict):
            continue
        payload = messages.get(key)
        if isinstance(payload, dict) and isinstance(payload.get("message"), str):
            return payload["message"]

    for candidate in sorted(locale_dir.iterdir()) if locale_dir.exists() else []:
        if not candidate.is_dir():
            continue
        messages = read_json(candidate / "messages.json")
        if not isinstance(messages, dict):
            continue
        payload = messages.get(key)
        if isinstance(payload, dict) and isinstance(payload.get("message"), str):
            return payload["message"]
    return value


def version_key(version: str) -> tuple[int, ...]:
    numeric = re.findall(r"\d+", version)
    return tuple(int(item) for item in numeric) if numeric else (0,)


def latest_manifest_path(extension_dir: Path) -> Path | None:
    versions = [path for path in extension_dir.iterdir() if path.is_dir()]
    if not versions:
        return None
    versions.sort(key=lambda item: (version_key(item.name), item.stat().st_mtime), reverse=True)
    for version_dir in versions:
        manifest = version_dir / "manifest.json"
        if manifest.exists():
            return manifest
    return None


def flatten_host_permissions(manifest: dict[str, Any]) -> list[str]:
    result = list(manifest.get("host_permissions") or [])
    result.extend(manifest.get("optional_host_permissions") or [])
    for content_script in manifest.get("content_scripts") or []:
        result.extend(content_script.get("matches") or [])
    return sorted({item for item in result if isinstance(item, str)})


def extract_permissions(manifest: dict[str, Any], key: str) -> list[str]:
    values = manifest.get(key) or []
    return sorted({item for item in values if isinstance(item, str)})


def extract_scripts(manifest: dict[str, Any]) -> list[str]:
    scripts: list[str] = []
    background = manifest.get("background") or {}
    if isinstance(background.get("service_worker"), str):
        scripts.append(background["service_worker"])
    scripts.extend(item for item in background.get("scripts", []) if isinstance(item, str))
    for content_script in manifest.get("content_scripts") or []:
        scripts.extend(item for item in content_script.get("js", []) if isinstance(item, str))
    return sorted(set(scripts))


def analyze_codebase(package_root: Path, manifest: dict[str, Any], permissions: list[str], host_permissions: list[str]) -> tuple[list[SuspiciousSignal], list[str]]:
    script_paths = []
    for pattern in ("*.js", "*.mjs", "*.cjs", "*.html", "*.json"):
        script_paths.extend(package_root.rglob(pattern))

    signals: list[SuspiciousSignal] = []
    timeline: list[str] = []
    snippets: list[str] = []

    text_blobs: list[str] = []
    for path in script_paths[:200]:
        try:
            if path.stat().st_size > 500_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        text_blobs.append(text)
        if len(text) > 0:
            snippets.append(f"{path.name}:{len(text)}")

    combined = "\n".join(text_blobs)

    if re.search(r"https?://[^\s\"']+", combined) and re.search(r"(alarms\.create|setInterval|setTimeout|fetch\(|XMLHttpRequest|axios\.)", combined):
        signals.append(
            SuspiciousSignal(
                code="remote_heartbeat",
                title="Remote heartbeat or configuration fetch",
                severity=28,
                detail="The package appears to contact external services on a schedule or during background activity.",
                evidence=re.findall(r"https?://[^\s\"']+", combined)[:5],
            )
        )
        timeline.append("Detected code patterns consistent with remote config or heartbeat traffic.")

    if re.search(r"createElement\s*\(\s*['\"]script['\"]\s*\)", combined) and re.search(r"\.src\s*=\s*['\"]https?://", combined):
        signals.append(
            SuspiciousSignal(
                code="remote_script_injection",
                title="Remote script injection",
                severity=35,
                detail="The extension appears to create script elements that load remote JavaScript into pages.",
                evidence=["Dynamic script element with remote src."],
            )
        )
        timeline.append("Detected dynamic loading of remote JavaScript into the page context.")

    if "content-security-policy" in combined or "modifyHeaders" in combined:
        signals.append(
            SuspiciousSignal(
                code="csp_tampering",
                title="CSP or header tampering",
                severity=30,
                detail="The package references header modification or CSP manipulation logic.",
                evidence=["content-security-policy", "modifyHeaders"],
            )
        )
        timeline.append("Detected request or response header tampering patterns.")

    obfuscation_markers = len(re.findall(r"_0x[a-f0-9]{4,}", combined, flags=re.IGNORECASE))
    eval_markers = len(re.findall(r"\beval\s*\(|\bFunction\s*\(", combined))
    if obfuscation_markers >= 12 or eval_markers >= 4:
        signals.append(
            SuspiciousSignal(
                code="obfuscation_or_eval",
                title="Heavy obfuscation or runtime code execution",
                severity=22,
                detail="The code contains multiple eval/Function calls or obfuscation markers common in concealment-heavy packages.",
                evidence=[f"obfuscation markers: {obfuscation_markers}", f"runtime exec markers: {eval_markers}"],
            )
        )
        timeline.append("Detected heavy obfuscation or runtime code construction.")

    normalized_hosts = set(host_permissions)
    if any(value in normalized_hosts for value in ["<all_urls>", "*://*/*"]) and {"cookies", "webRequest", "tabs"} & set(permissions):
        signals.append(
            SuspiciousSignal(
                code="broad_host_cookie_combo",
                title="Broad host access with session-sensitive permissions",
                severity=20,
                detail="The extension can access broad host scopes alongside permissions often involved in session inspection or interception.",
                evidence=sorted({"cookies", "webRequest", "tabs"} & set(permissions)),
            )
        )
        timeline.append("Detected a powerful combination of all-sites access and session-sensitive permissions.")

    narrow_words = " ".join(
        value.lower()
        for value in [
            str(manifest.get("name", "")),
            str(manifest.get("description", "")),
        ]
    )
    if any(keyword in narrow_words for keyword in NARROW_PURPOSE_KEYWORDS) and (
        any(value in normalized_hosts for value in ["<all_urls>", "*://*/*"]) or {"cookies", "webRequestBlocking", "proxy"} & set(permissions)
    ):
        signals.append(
            SuspiciousSignal(
                code="purpose_permission_mismatch",
                title="Purpose-permission mismatch",
                severity=18,
                detail="The extension describes a narrow feature set but requests unusually broad browser access.",
                evidence=[manifest.get("name", ""), manifest.get("description", "")],
            )
        )
        timeline.append("Detected a mismatch between the stated purpose and the requested access scope.")

    if not timeline:
        timeline.append("No high-confidence malicious code patterns were detected in the local package scan.")

    return signals, timeline


def compute_power_score(permissions: list[str], host_permissions: list[str]) -> int:
    score = 0
    for permission in permissions:
        score += POWER_WEIGHTS.get(permission, 2)
    for permission in host_permissions:
        score += POWER_WEIGHTS.get(permission, 0)
    if any(host in {"<all_urls>", "*://*/*"} for host in host_permissions):
        score += 10
    return min(score, 100)


def compute_suspicion_score(signals: list[SuspiciousSignal], intel_count: int, store_status: str) -> int:
    score = sum(signal.severity for signal in signals)
    if intel_count:
        score += 40
    if store_status == "unavailable_or_removed":
        score += 20
    return min(score, 100)


def choose_verdict(
    enabled_state: str,
    power_score: int,
    suspicion_score: int,
    intel_count: int,
    store_status: str,
) -> str:
    if intel_count:
        return "known_malicious"
    if enabled_state == "disabled_by_chrome":
        return "disabled_by_chrome"
    if store_status == "unavailable_or_removed":
        return "removed_or_unavailable"
    if suspicion_score >= 45:
        return "suspicious"
    if power_score >= 40:
        return "powerful_but_expected"
    if power_score >= 0:
        return "low_concern"
    return "unknown"


def determine_enabled_state(pref_entry: dict[str, Any]) -> str:
    state_value = pref_entry.get("state")
    if isinstance(state_value, int):
        label = STATE_LABELS.get(state_value, "unknown")
        if label == "blacklisted":
            return "disabled_by_chrome"
        return label

    disable_reasons = pref_entry.get("disable_reasons")
    if disable_reasons:
        return "disabled_by_chrome"
    return "unknown"


def determine_install_source(pref_entry: dict[str, Any]) -> str:
    location = pref_entry.get("location")
    if isinstance(location, int):
        return LOCATION_LABELS.get(location, f"unknown({location})")
    return "unknown"


def collect_profile_installs(channel_family: str, channel_name: str, root: Path, profile_path: Path, profile_name: str) -> list[RawInstall]:
    preferences = read_json(profile_path / "Preferences") or {}
    extension_settings = preferences.get("extensions", {}).get("settings", {})
    extensions_dir = profile_path / "Extensions"
    if not extensions_dir.exists():
        return []

    installs: list[RawInstall] = []
    for extension_dir in extensions_dir.iterdir():
        if not extension_dir.is_dir():
            continue
        manifest_path = latest_manifest_path(extension_dir)
        if not manifest_path:
            continue
        manifest = read_json(manifest_path)
        if not manifest:
            continue

        default_locale = manifest.get("default_locale")
        package_root = manifest_path.parent
        raw_name = str(manifest.get("name", extension_dir.name))
        raw_description = str(manifest.get("description", ""))
        name = resolve_localized_value(raw_name, package_root, default_locale)
        description = resolve_localized_value(raw_description, package_root, default_locale)
        pref_entry = extension_settings.get(extension_dir.name, {}) if isinstance(extension_settings, dict) else {}

        permissions = extract_permissions(manifest, "permissions")
        optional_permissions = extract_permissions(manifest, "optional_permissions")
        host_permissions = flatten_host_permissions(manifest)
        optional_host_permissions = extract_permissions(manifest, "optional_host_permissions")
        signals, timeline = analyze_codebase(package_root, manifest, permissions, host_permissions)

        info = {
            "id": extension_dir.name,
            "name": name,
            "description": description,
            "version": str(manifest.get("version", "unknown")),
            "manifest_version": int(manifest.get("manifest_version", 2)),
            "permissions": permissions,
            "optional_permissions": optional_permissions,
            "host_permissions": host_permissions,
            "optional_host_permissions": optional_host_permissions,
            "content_script_matches": flatten_host_permissions({"content_scripts": manifest.get("content_scripts")}),
            "homepage_url": manifest.get("homepage_url"),
            "author": manifest.get("author"),
        }

        profile_install = ProfileInstall(
            profile_id=profile_path.name,
            profile_name=profile_name,
            browser_channel=channel_name,
            browser_family=channel_family,
            enabled_state=determine_enabled_state(pref_entry if isinstance(pref_entry, dict) else {}),
            install_source=determine_install_source(pref_entry if isinstance(pref_entry, dict) else {}),
            version=info["version"],
            manifest_path=str(manifest_path),
        )
        installs.append(
            RawInstall(
                extension_id=extension_dir.name,
                profile_install=profile_install,
                info=info,
                suspicious_signals=signals,
                power_score=compute_power_score(permissions + optional_permissions, host_permissions + optional_host_permissions),
                suspicion_score=sum(signal.severity for signal in signals),
                evidence_timeline=timeline,
            )
        )
    return installs


def aggregate_installs(raw_installs: list[RawInstall], enable_live_checks: bool, enable_ai: bool) -> list[ExtensionFinding]:
    grouped: dict[str, list[RawInstall]] = defaultdict(list)
    for item in raw_installs:
        grouped[item.extension_id].append(item)

    findings: list[ExtensionFinding] = []
    for extension_id, installs in grouped.items():
        installs.sort(key=lambda item: (version_key(item.info["version"]), item.profile_install.profile_name), reverse=True)
        primary = installs[0]
        permissions = sorted({perm for item in installs for perm in item.info["permissions"]})
        optional_permissions = sorted({perm for item in installs for perm in item.info["optional_permissions"]})
        host_permissions = sorted({perm for item in installs for perm in item.info["host_permissions"]})
        optional_host_permissions = sorted({perm for item in installs for perm in item.info["optional_host_permissions"]})
        content_matches = sorted({match for item in installs for match in item.info["content_script_matches"]})
        signals: dict[str, SuspiciousSignal] = {}
        timeline: list[str] = []
        for item in installs:
            timeline.extend(item.evidence_timeline)
            for signal in item.suspicious_signals:
                current = signals.get(signal.code)
                if current is None or current.severity < signal.severity:
                    signals[signal.code] = signal

        intel_matches = lookup_intel(extension_id)
        store_status = "not_checked"
        if enable_live_checks:
            store_status = lookup_store_status(extension_id).status

        enabled_state = (
            "disabled_by_chrome"
            if any(profile.profile_install.enabled_state == "disabled_by_chrome" for profile in installs)
            else primary.profile_install.enabled_state
        )
        power_score = min(max(item.power_score for item in installs), 100)
        suspicion_score = compute_suspicion_score(list(signals.values()), len(intel_matches), store_status)
        verdict = choose_verdict(enabled_state, power_score, suspicion_score, len(intel_matches), store_status)

        finding = ExtensionFinding(
            id=extension_id,
            name=primary.info["name"],
            version=primary.info["version"],
            description=primary.info["description"],
            manifest_version=primary.info["manifest_version"],
            permissions=permissions,
            optional_permissions=optional_permissions,
            host_permissions=host_permissions,
            optional_host_permissions=optional_host_permissions,
            content_script_matches=content_matches,
            profiles=[item.profile_install for item in sorted(installs, key=lambda value: value.profile_install.profile_name)],
            power_score=power_score,
            suspicion_score=suspicion_score,
            verdict=verdict,
            store_status=store_status,
            suspicious_signals=sorted(signals.values(), key=lambda signal: signal.severity, reverse=True),
            intel_matches=intel_matches,
            evidence_timeline=list(dict.fromkeys(timeline)),
            package_root=str(Path(primary.profile_install.manifest_path).parent),
            homepage_url=primary.info["homepage_url"],
            author=primary.info["author"],
        )
        findings.append(finding)
    findings.sort(key=lambda item: (item.verdict != "known_malicious", -item.suspicion_score, -item.power_score, item.name.lower()))
    return findings


def scan_local_extensions(options: ScanOptions) -> list[ExtensionFinding]:
    raw_installs: list[RawInstall] = []
    roots = discover_channel_roots(options.roots)
    requested_channels = {channel.lower() for channel in options.channels or []}

    for family, channel, root in roots:
        if requested_channels and channel.lower() not in requested_channels and family.lower() not in requested_channels:
            continue
        profile_names = load_profile_names(root)
        for profile_path in discover_profiles(root, options.profiles):
            profile_name = profile_names.get(profile_path.name, profile_path.name)
            raw_installs.extend(collect_profile_installs(family, channel, root, profile_path, profile_name))
    return aggregate_installs(raw_installs, options.enable_live_checks, options.enable_ai)


def import_legacy_csv(filename: str, content: bytes) -> list[ExtensionFinding]:
    rows = list(csv.DictReader(content.decode("utf-8", errors="ignore").splitlines()))
    findings: list[ExtensionFinding] = []
    for index, row in enumerate(rows):
        extension_id = row.get("extension_id") or row.get("Extension ID") or f"imported-{index}"
        verdict = "unknown"
        risk_level = (row.get("Risk Level") or "").lower()
        if "high" in risk_level:
            verdict = "powerful_but_expected"
        elif "medium" in risk_level:
            verdict = "suspicious"
        elif "low" in risk_level:
            verdict = "low_concern"

        findings.append(
            ExtensionFinding(
                id=str(extension_id),
                name=row.get("Name") or "Imported Extension",
                version=row.get("Version") or "unknown",
                description=f"Imported from {filename}",
                manifest_version=0,
                permissions=[],
                optional_permissions=[],
                host_permissions=[],
                optional_host_permissions=[],
                content_script_matches=[],
                profiles=[
                    ProfileInstall(
                        profile_id="imported",
                        profile_name="Imported CSV",
                        browser_channel="imported",
                        browser_family="imported",
                        enabled_state="unknown",
                        install_source="imported_csv",
                        version=row.get("Version") or "unknown",
                        manifest_path=filename,
                    )
                ],
                power_score=int((row.get("Power Score") or row.get("Permissions") or "0").split("/")[0]) if row.get("Power Score") else 0,
                suspicion_score=int((row.get("Suspicion Score") or "0").split("/")[0]) if row.get("Suspicion Score") else 0,
                verdict=verdict,
                store_status=row.get("store_status") or "unknown",
                ai_summary=None,
                evidence_timeline=[f"Imported from legacy CSV: {filename}"],
            )
        )
    return findings
