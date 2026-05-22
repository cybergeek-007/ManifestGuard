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

from backend.allowlist import is_trusted, lookup_allowlist
from backend.intel import lookup_intel
from backend.models import ExtensionFinding, ProfileInstall, ScanOptions, SuspiciousSignal
from backend.reputation import compute_reputation_adjustment, fetch_reputation
from backend.store import lookup_store_status

# ── Trusted extension allowlist is now in backend/allowlist.py ──────

# ── Category inference keywords ──────────────────────────────
CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "password_manager": ["password", "vault", "login", "credential", "autofill", "passkey"],
    "ad_blocker": ["ad block", "adblock", "ad-block", "tracker", "anti-track", "content blocker"],
    "privacy_tool": ["privacy", "vpn", "proxy", "encrypt", "anonymous", "do not track"],
    "developer_tool": ["devtools", "developer tool", "debug", "inspector", "react dev", "vue dev", "redux", "json viewer", "web developer"],
    "security_tool": ["security", "antivirus", "malware", "phishing", "guard", "protect"],
    "productivity": ["grammar", "translate", "todoist", "notion", "evernote", "clipboard", "tab manager"],
    "communication": ["zoom", "slack", "teams", "meet", "chat", "messenger", "discord", "telegram"],
    "shopping": ["coupon", "cashback", "price", "deal", "shopping", "honey", "discount"],
    "accessibility": ["dark mode", "dark reader", "high contrast", "screen reader", "text to speech", "dyslexia"],
    "media": ["youtube", "video", "spotify", "music", "picture in picture", "pip", "volume"],
}

# Permissions expected for each category — these should NOT trigger suspicion
CATEGORY_EXPECTED_PERMISSIONS: dict[str, set[str]] = {
    "password_manager": {"<all_urls>", "*://*/*", "cookies", "tabs", "webRequest", "storage", "activeTab", "scripting", "clipboardRead", "clipboardWrite"},
    "ad_blocker": {"<all_urls>", "*://*/*", "webRequest", "webRequestBlocking", "declarativeNetRequest", "tabs", "storage"},
    "privacy_tool": {"<all_urls>", "*://*/*", "webRequest", "webRequestBlocking", "proxy", "cookies", "tabs", "storage"},
    "developer_tool": {"<all_urls>", "*://*/*", "tabs", "activeTab", "debugger", "scripting", "storage"},
    "security_tool": {"<all_urls>", "*://*/*", "webRequest", "webRequestBlocking", "tabs", "cookies", "management", "storage"},
    "productivity": {"<all_urls>", "*://*/*", "activeTab", "tabs", "storage", "clipboardRead", "clipboardWrite"},
    "communication": {"<all_urls>", "*://*/*", "tabs", "activeTab", "storage", "notifications", "desktopCapture"},
    "shopping": {"<all_urls>", "*://*/*", "tabs", "activeTab", "storage", "cookies"},
    "accessibility": {"<all_urls>", "*://*/*", "tabs", "activeTab", "storage", "scripting"},
    "media": {"<all_urls>", "*://*/*", "tabs", "activeTab", "storage"},
}

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


def _lookup_message_key(messages: dict[str, Any], key: str) -> str | None:
    """Case-insensitive lookup in a messages.json dict."""
    # Try exact match first
    payload = messages.get(key)
    if isinstance(payload, dict) and isinstance(payload.get("message"), str):
        return payload["message"]
    # Try case-insensitive match
    key_lower = key.lower()
    for msg_key, msg_payload in messages.items():
        if msg_key.lower() == key_lower and isinstance(msg_payload, dict) and isinstance(msg_payload.get("message"), str):
            return msg_payload["message"]
    return None


def resolve_localized_value(value: str, manifest_dir: Path, default_locale: str | None) -> str:
    key = parse_message_key(value)
    if not key:
        return value

    locale_candidates: list[str] = []
    if default_locale:
        locale_candidates.append(default_locale)
        # Try variant: en_US -> en, en -> en_US
        if "_" in default_locale:
            locale_candidates.append(default_locale.split("_")[0])
        else:
            locale_candidates.append(f"{default_locale}_US")
    locale_candidates.extend(["en", "en_US", "en_GB"])

    locale_dir = manifest_dir / "_locales"
    checked: set[str] = set()

    # Phase 1: Try preferred locales
    for locale in locale_candidates:
        if not locale or locale in checked:
            continue
        checked.add(locale)
        messages = read_json(locale_dir / locale / "messages.json")
        if not isinstance(messages, dict):
            continue
        result = _lookup_message_key(messages, key)
        if result:
            return result

    # Phase 2: Try every locale directory (sorted so results are deterministic)
    try:
        locale_dirs = sorted(locale_dir.iterdir()) if locale_dir.exists() else []
    except OSError:
        locale_dirs = []

    for candidate in locale_dirs:
        if not candidate.is_dir() or candidate.name in checked:
            continue
        messages = read_json(candidate / "messages.json")
        if not isinstance(messages, dict):
            continue
        result = _lookup_message_key(messages, key)
        if result:
            return result

    # Phase 3: Return the raw value stripped of __MSG_ wrapper so it's at least readable
    # Instead of showing "__MSG_appName__", show "appName"
    return key.replace("_", " ").title()


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

    # Tuned remote heartbeat: Require actual fetch/XHR API usage near a URL or high confidence heartbeat APIs
    # instead of just any HTTP string in the entire bundle.
    has_network_api = bool(re.search(r'(?:fetch|axios\.[a-z]+|\$\.(?:ajax|get|post))\s*\(|XMLHttpRequest|sendBeacon', combined))
    has_heartbeat_api = bool(re.search(r'alarms\.create|setInterval|setTimeout', combined))
    has_url = bool(re.search(r"https?://[^\s\"']+", combined))
    
    if has_url and has_network_api and has_heartbeat_api:
        signals.append(
            SuspiciousSignal(
                code="remote_heartbeat",
                title="Remote heartbeat or configuration fetch",
                severity=15,  # Lowered from 28 because network requests are common
                detail="The package appears to contact external services on a schedule or during background activity.",
                evidence=["fetch/XHR + setInterval/alarms + URL present"],
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

    # Fixed: require BOTH a CSP reference AND active header modification API usage
    # plus the webRequest/declarativeNetRequest permission to avoid flagging ad blockers
    has_csp_ref = "content-security-policy" in combined.lower()
    has_modify = "modifyHeaders" in combined
    has_modify_perm = {"webRequest", "webRequestBlocking", "declarativeNetRequest"} & set(permissions)
    if has_csp_ref and has_modify and has_modify_perm:
        signals.append(
            SuspiciousSignal(
                code="csp_tampering",
                title="CSP or header tampering",
                severity=18,  # Lowered from 30
                detail="The extension actively modifies Content-Security-Policy headers using browser APIs.",
                evidence=["content-security-policy + modifyHeaders"],
            )
        )
        timeline.append("Detected active request/response header tampering patterns.")

    obfuscation_markers = len(re.findall(r"_0x[a-f0-9]{4,}", combined, flags=re.IGNORECASE))
    eval_markers = len(re.findall(r"\beval\s*\(|\bFunction\s*\(", combined))
    if obfuscation_markers >= 20 or eval_markers >= 10:
        signals.append(
            SuspiciousSignal(
                code="obfuscation_or_eval",
                title="Heavy obfuscation or runtime code execution",
                severity=15,  # Lowered from 22
                detail="The code contains multiple eval/Function calls or obfuscation markers.",
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

    # ── NEW SIGNALS (v3) ──────────────────────────────────────

    # Data exfiltration: reading cookies/storage + sending externally
    has_cookie_read = bool(re.search(r'chrome\.cookies\.getAll|chrome\.cookies\.get\(', combined))
    has_external_send = bool(re.search(r'fetch\s*\(|XMLHttpRequest|\$\.ajax|axios\.|sendBeacon', combined))
    if has_cookie_read and has_external_send:
        signals.append(
            SuspiciousSignal(
                code="data_exfiltration",
                title="Data exfiltration pattern",
                severity=32,
                detail="The extension reads browser cookies/storage AND sends data to external servers — a classic data harvesting pattern.",
                evidence=["chrome.cookies.getAll + external fetch/XHR"],
            )
        )
        timeline.append("Detected cookie/data reading combined with external data transmission.")

    # Keylogger: listening to keydown/keypress on document/window
    if re.search(r'addEventListener\s*\(\s*[\'"]key(?:down|press|up)[\'"]', combined) and (
        re.search(r'document\.addEventListener|window\.addEventListener', combined)
    ):
        signals.append(
            SuspiciousSignal(
                code="keylogger_pattern",
                title="Keylogger behavior",
                severity=35,
                detail="The extension listens for keyboard events on the document/window level — a pattern commonly used for keystroke logging.",
                evidence=["document/window keydown/keypress listener"],
            )
        )
        timeline.append("Detected document-level keyboard event interception.")

    # Screen capture
    if re.search(r'chrome\.tabs\.captureVisibleTab|getDisplayMedia|captureStream', combined):
        signals.append(
            SuspiciousSignal(
                code="screen_capture",
                title="Screen capture capability",
                severity=28,
                detail="The extension can capture screenshots or screen recordings of browser tabs.",
                evidence=re.findall(r'captureVisibleTab|getDisplayMedia|captureStream', combined)[:3],
            )
        )
        timeline.append("Detected screen/tab capture capability.")

    # Clipboard theft
    if re.search(r'navigator\.clipboard\.readText|document\.execCommand\s*\(\s*[\'"]paste[\'"]', combined):
        signals.append(
            SuspiciousSignal(
                code="clipboard_theft",
                title="Clipboard reading",
                severity=25,
                detail="The extension reads clipboard content — could be used to steal copied passwords, keys, or sensitive data.",
                evidence=["navigator.clipboard.readText or execCommand('paste')"],
            )
        )
        timeline.append("Detected clipboard content reading.")

    # Crypto mining patterns
    if re.search(r'WebAssembly\.instantiate|WebAssembly\.compile', combined) and (
        re.search(r'stratum|coinhive|cryptonight|minergate|hashrate', combined, re.IGNORECASE)
        or re.search(r'SharedArrayBuffer|postMessage.*worker', combined)
    ):
        signals.append(
            SuspiciousSignal(
                code="crypto_mining",
                title="Potential crypto mining",
                severity=30,
                detail="The extension loads WebAssembly modules with patterns associated with cryptocurrency mining.",
                evidence=["WebAssembly + mining pool indicators"],
            )
        )
        timeline.append("Detected WebAssembly usage with crypto mining indicators.")

    # Credential form access
    if re.search(r'querySelector(?:All)?\s*\(\s*[\'"].*(?:input\[type.*password|type=[\'"]password)', combined) and (
        re.search(r'\.value', combined)
    ):
        signals.append(
            SuspiciousSignal(
                code="credential_access",
                title="Credential form access",
                severity=30,
                detail="The extension accesses password input fields and reads their values — legitimate for password managers, suspicious for others.",
                evidence=["querySelector('input[type=password]') + .value access"],
            )
        )
        timeline.append("Detected password field value extraction.")

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


def infer_category(name: str, description: str, permissions: list[str]) -> str | None:
    """Heuristically determine the extension's functional category."""
    text = f"{name} {description}".lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return category
    return None


def compute_suspicion_score(
    signals: list[SuspiciousSignal],
    intel_count: int,
    store_status: str,
    extension_id: str = "",
    category: str | None = None,
    permissions: list[str] | None = None,
) -> int:
    # Start with raw signal severity sum
    filtered_signals = list(signals)

    # If extension belongs to a known category, remove signals caused by expected permissions
    if category and category in CATEGORY_EXPECTED_PERMISSIONS:
        expected = CATEGORY_EXPECTED_PERMISSIONS[category]
        actual_perms = set(permissions or [])
        # If all the extension's permissions are expected for its category,
        # reduce the severity of the broad_host_cookie_combo signal
        if actual_perms <= expected:
            filtered_signals = [
                s for s in filtered_signals
                if s.code != "broad_host_cookie_combo" and s.code != "purpose_permission_mismatch"
            ]

    # If extension is on the trusted allowlist, zero out all code-level signals
    if is_trusted(extension_id):
        filtered_signals = [s for s in filtered_signals if s.code not in {
            "broad_host_cookie_combo", "purpose_permission_mismatch", "csp_tampering",
            "credential_access", "keylogger_pattern", "data_exfiltration", 
            "screen_capture", "clipboard_theft",
        }]

    score = sum(signal.severity for signal in filtered_signals)
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
    extension_id: str = "",
    reputation_score: int = -1,
) -> str:
    # Intel match always wins (overrides even trusted)
    if intel_count:
        return "known_malicious"
    # Trusted extensions bypass suspicion-based verdicts
    if is_trusted(extension_id) and suspicion_score < 40:
        return "trusted"
    if enabled_state == "disabled_by_chrome":
        return "disabled_by_chrome"
    if store_status == "unavailable_or_removed":
        return "removed_or_unavailable"
    if suspicion_score >= 40:
        return "suspicious"
    # NEW: moderate_risk — fills gap between suspicious and expected
    if suspicion_score >= 25 and power_score >= 50:
        return "moderate_risk"
    if power_score >= 40 and (reputation_score < 0 or reputation_score > 50):
        return "powerful_but_expected"
    if power_score >= 40:
        return "powerful_but_expected"
    return "low_concern"


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
        # Only count granted permissions for power score (not optional ones)
        installs.append(
            RawInstall(
                extension_id=extension_dir.name,
                profile_install=profile_install,
                info=info,
                suspicious_signals=signals,
                power_score=compute_power_score(permissions, host_permissions),
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
        # Infer category for purpose-permission alignment
        category = infer_category(
            primary.info["name"],
            primary.info["description"],
            permissions,
        )
        power_score = min(max(item.power_score for item in installs), 100)
        raw_suspicion = compute_suspicion_score(
            list(signals.values()), len(intel_matches), store_status,
            extension_id=extension_id, category=category, permissions=permissions,
        )

        # ── Reputation integration (v3) ──────────────────────
        reputation_score = -1
        reputation_details = None
        if enable_live_checks:
            try:
                rep = fetch_reputation(extension_id)
                if rep.lookup_status == "success":
                    reputation_score = rep.reputation_score
                    reputation_details = rep.to_dict()
                    # Apply reputation adjustment to suspicion
                    adjustment = compute_reputation_adjustment(reputation_score)
                    adjusted_suspicion = int(raw_suspicion * adjustment)
                else:
                    adjusted_suspicion = raw_suspicion
            except Exception:
                adjusted_suspicion = raw_suspicion
        else:
            adjusted_suspicion = raw_suspicion

        suspicion_score = min(adjusted_suspicion, 100)
        verdict = choose_verdict(
            enabled_state, power_score, suspicion_score, len(intel_matches),
            store_status, extension_id=extension_id,
            reputation_score=reputation_score,
        )

        # ── Recommendations for flagged extensions (v3) ──────
        recommendations: list[dict] = []
        if verdict in ("suspicious", "moderate_risk", "known_malicious"):
            try:
                from backend.recommendations import get_recommendations
                recs = get_recommendations(
                    primary.info["name"], primary.info["description"], category
                )
                recommendations = [r.to_dict() for r in recs]
            except Exception:
                pass

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
            category=category,
            reputation_score=reputation_score,
            reputation_details=reputation_details,
            adjusted_suspicion_score=suspicion_score,
            recommendations=recommendations,
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
