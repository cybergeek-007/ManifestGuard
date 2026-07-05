"""ManifestGuard v4 — Core Scanning Engine.

Online-only scanning engine. All local filesystem scanning has been removed.
Score names: reach_score (was power_score), anomaly_score (was suspicion_score).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from backend.allowlist import is_trusted
from backend.intel import lookup_intel
from backend.models import ExtensionFinding, ProfileInstall, ScanOptions, SuspiciousSignal
from backend.reputation import compute_reputation_adjustment, fetch_reputation
from backend.store import lookup_store_status

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

# Permissions expected for each category — these should NOT trigger anomaly
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

# v4: renamed from POWER_WEIGHTS
REACH_WEIGHTS = {
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


# ── Helper functions ──────────────────────────────────────

def read_json(path: Path) -> dict | None:
    try:
        import json
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def parse_message_key(value: str) -> str | None:
    m = re.match(r"^__MSG_(\w+)__$", value, re.IGNORECASE)
    return m.group(1) if m else None


def _lookup_message_key(messages: dict, key: str) -> str | None:
    for k, v in messages.items():
        if k.lower() == key.lower():
            if isinstance(v, dict):
                return v.get("message", v.get("Message"))
            return None
    return None


def resolve_localized_value(
    value: str,
    manifest_dir: Path,
    default_locale: str | None = None,
) -> str:
    key = parse_message_key(value)
    if not key:
        return value

    locales_dir = manifest_dir / "_locales"
    if not locales_dir.exists():
        return value

    candidate_locales = []
    if default_locale:
        candidate_locales.append(default_locale)
    candidate_locales.extend(["en", "en_US", "en_GB"])

    for locale in candidate_locales:
        messages_path = locales_dir / locale / "messages.json"
        if messages_path.exists():
            messages = read_json(messages_path)
            if messages:
                resolved = _lookup_message_key(messages, key)
                if resolved:
                    return resolved

    # Try any available locale
    for locale_dir in locales_dir.iterdir():
        if locale_dir.is_dir():
            messages_path = locale_dir / "messages.json"
            if messages_path.exists():
                messages = read_json(messages_path)
                if messages:
                    resolved = _lookup_message_key(messages, key)
                    if resolved:
                        return resolved

    return value


def version_key(version: str) -> tuple:
    try:
        return tuple(int(p) for p in version.split("."))
    except (ValueError, AttributeError):
        return (0,)


def flatten_host_permissions(manifest: dict) -> list[str]:
    hosts = list(manifest.get("host_permissions", []))
    hosts.extend(manifest.get("optional_host_permissions", []))
    for cs in manifest.get("content_scripts", []):
        hosts.extend(cs.get("matches", []))
    return sorted(set(hosts))


def extract_permissions(manifest: dict, key: str = "permissions") -> list[str]:
    return sorted(set(manifest.get(key, [])))


def extract_scripts(manifest: dict) -> list[str]:
    scripts = []
    bg = manifest.get("background", {})
    scripts.extend(bg.get("scripts", []))
    if sw := bg.get("service_worker"):
        scripts.append(sw)
    for cs in manifest.get("content_scripts", []):
        scripts.extend(cs.get("js", []))
    return scripts


# ── Codebase analysis ──────────────────────────────────

def analyze_codebase(package_root: Path, manifest: dict[str, Any], permissions: list[str], host_permissions: list[str]) -> tuple[list[SuspiciousSignal], list[str], str, str]:
    script_paths = []
    for pattern in ("*.js", "*.mjs", "*.cjs", "*.html", "*.json"):
        script_paths.extend(package_root.rglob(pattern))

    signals: list[SuspiciousSignal] = []
    timeline: list[str] = []
    snippets: list[str] = []
    text_blobs: list[str] = []

    background_files = set()
    bg = manifest.get("background", {})
    background_files.update(bg.get("scripts", []))
    if sw := bg.get("service_worker"):
        background_files.add(sw)
        
    background_snippet = ""
    largest_obfuscated_string = ""

    for path in script_paths[:200]:
        try:
            # v4: skip files > 1MB (likely bundled libraries)
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            
            # Phase 2: capture first 50 lines of background script
            if path.name in background_files and not background_snippet:
                lines = text.splitlines()[:50]
                background_snippet = "\n".join(lines)
                
            # Phase 2: capture largest obfuscated string if obfuscated
            if "_0x" in text:
                matches = re.findall(r"['\"](_0x[a-f0-9]{4,}.*?)['\"]", text, re.IGNORECASE)
                for m in matches:
                    if len(m) > len(largest_obfuscated_string) and len(m) <= 1000:
                        largest_obfuscated_string = m
                        
        except Exception:
            continue
        text_blobs.append(text)
        if len(text) > 0:
            snippets.append(f"{path.name}:{len(text)}")

    combined = "\n".join(text_blobs)

    # Tuned remote heartbeat: Require actual fetch/XHR API usage near a URL or high confidence heartbeat APIs
    has_network_api = bool(re.search(r'(?:fetch|axios\.[a-z]+|\$\.(?:ajax|get|post))\s*\(|XMLHttpRequest|sendBeacon', combined))
    has_heartbeat_api = bool(re.search(r'alarms\.create|setInterval|setTimeout', combined))
    has_url = bool(re.search(r"https?://[^\s\"']+", combined))
    
    if has_url and has_network_api and has_heartbeat_api:
        signals.append(
            SuspiciousSignal(
                code="remote_heartbeat",
                title="Remote heartbeat or configuration fetch",
                severity=15,
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

    has_csp_ref = "content-security-policy" in combined.lower()
    has_modify = "modifyHeaders" in combined
    has_modify_perm = {"webRequest", "webRequestBlocking", "declarativeNetRequest"} & set(permissions)
    if has_csp_ref and has_modify and has_modify_perm:
        signals.append(
            SuspiciousSignal(
                code="csp_tampering",
                title="CSP or header tampering",
                severity=18,
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
                severity=15,
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

    # ── Data exfiltration ─────────────────────────────────
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

    # Keylogger
    if re.search(r'addEventListener\s*\(\s*[\'\"]key(?:down|press|up)[\'\"]', combined) and (
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
    if re.search(r'navigator\.clipboard\.readText|document\.execCommand\s*\(\s*[\'\"]paste[\'\"]', combined):
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
    if re.search(r'querySelector(?:All)?\s*\(\s*[\'\"].*(?:input\[type.*password|type=[\'\"]password)', combined) and (
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
        timeline.append("No high-confidence malicious code patterns were detected in the source code scan.")

    return signals, timeline, background_snippet, largest_obfuscated_string


# ── Scoring functions ──────────────────────────────────


def compute_reach_score(permissions: list[str], host_permissions: list[str]) -> int:
    """Compute the Reach Score (v4: renamed from Power Score).

    Measures the breadth of host/permission access an extension has.
    """
    score = 0
    for permission in permissions:
        score += REACH_WEIGHTS.get(permission, 2)
    for permission in host_permissions:
        score += REACH_WEIGHTS.get(permission, 0)
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


def compute_anomaly_score(
    signals: list[SuspiciousSignal],
    intel_count: int,
    store_status: str,
    extension_id: str = "",
    category: str | None = None,
    permissions: list[str] | None = None,
) -> int:
    """Compute the Behavioral Anomaly Score (v4: renamed from Suspicion Score).

    Measures weird code patterns, heuristic signal severity, and static intel.
    """
    filtered_signals = list(signals)

    # If extension belongs to a known category, remove signals caused by expected permissions
    if category and category in CATEGORY_EXPECTED_PERMISSIONS:
        expected = CATEGORY_EXPECTED_PERMISSIONS[category]
        actual_perms = set(permissions or [])
        if actual_perms <= expected:
            filtered_signals = [
                s for s in filtered_signals
                if s.code != "broad_host_cookie_combo" and s.code != "purpose_permission_mismatch"
            ]

    # If extension is on the trusted allowlist, zero out most code-level signals
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
    reach_score: int,
    anomaly_score: int,
    intel_count: int,
    store_status: str,
    extension_id: str = "",
    reputation_score: int = -1,
) -> tuple[str, str | None]:
    """V4 verdict ladder — deterministic, evidence-based.

    Returns (verdict, sub_verdict) tuple.

    Verdicts: known_malicious, suspicious, moderate_risk, trusted, low_concern.
    """
    # 1. Hard override — confirmed threat intel match
    if intel_count > 0:
        return "known_malicious", "Threat Intel Match"

    # 2. CWS removed — escalate but NOT to known_malicious
    #    Many legitimate extensions get delisted. Only escalate to known_malicious
    #    if there are also suspicious signals.
    if store_status == "unavailable_or_removed":
        if anomaly_score >= 40:
            return "known_malicious", "CWS Removed + Suspicious Behavior"
        return "moderate_risk", "CWS Removed"

    # 3. Allowlist fast-path — if explicitly trusted and no intel match
    if is_trusted(extension_id):
        return "trusted", "Allowlist"

    # 4. High anomaly — suspicious regardless of reputation
    if anomaly_score >= 70:
        return "suspicious", None

    # 5. High anomaly + low/unknown reputation → suspicious
    if anomaly_score >= 50 and reputation_score < 40:
        return "suspicious", None

    # 6. Moderate anomaly + any concern → moderate_risk
    if anomaly_score >= 30 and reputation_score < 50:
        return "moderate_risk", None

    # 7. High reach + low reputation → moderate_risk (even without anomaly)
    if reach_score >= 60 and reputation_score < 30 and reputation_score >= 0:
        return "moderate_risk", "High Reach, Low Reputation"

    # 8. High reach + high reputation → trusted
    if reach_score >= 40 and reputation_score >= 70:
        return "trusted", "High Reach, Verified"

    # 9. Low reach + clean behavior → low_concern
    if reach_score < 30 and anomaly_score < 15:
        return "low_concern", None

    # 10. Unknown reputation — be cautious
    if reputation_score < 0:
        if anomaly_score >= 20:
            return "moderate_risk", "Unknown Publisher"
        if reach_score >= 50:
            return "moderate_risk", "Unknown Publisher, High Reach"
        return "low_concern", None

    # 11. Known reputation, low anomaly → trusted
    if reputation_score >= 50 and anomaly_score < 20:
        return "trusted", None

    # 12. Catch-all — moderate reach or moderate anomaly
    if anomaly_score >= 15 or reach_score >= 40:
        return "moderate_risk", None

    return "low_concern", None

