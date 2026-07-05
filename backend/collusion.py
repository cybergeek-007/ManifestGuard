"""ManifestGuard v4 — Cross-Extension Collusion Graph.

Analyzes collusion risks between multiple co-installed browser extensions.
When the companion extension sends all installed extensions, we parse each
extension's manifest for `externally_connectable`, `web_accessible_resources`,
and shared external domains to detect dangerous cross-extension relationships.

Collusion attacks work by splitting malicious behavior across two or more
extensions that individually appear benign. Extension A might harvest cookies
and forward them via `externally_connectable` to Extension B, which has
`webRequest` permission to exfiltrate them to a C2 server.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Any

from backend.models import CollusionEdge


# Domains to ignore when checking for shared external domains
_SAFE_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "chrome.google.com",
    "mozilla.org", "github.com", "githubusercontent.com",
    "cloudflare.com", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net", "npmjs.com",
    "facebook.com", "twitter.com", "microsoft.com", "apple.com",
    "amazon.com", "w3.org", "chromium.org",
}

# Permissions that make collusion dangerous
_SENSITIVE_PERMISSIONS = {
    "cookies", "webRequest", "webRequestBlocking", "tabs",
    "clipboardRead", "history", "management", "debugger",
    "<all_urls>", "*://*/*",
}


@dataclass(slots=True)
class CollusionReport:
    """Summary of cross-extension collusion analysis."""

    edges: list[CollusionEdge] = field(default_factory=list)
    affected_extension_ids: set[str] = field(default_factory=set)
    risk_summary: str = "No cross-extension collusion risks detected."

    def to_dict(self) -> dict[str, Any]:
        return {
            "edges": [e.to_dict() for e in self.edges],
            "affectedExtensionIds": sorted(self.affected_extension_ids),
            "riskSummary": self.risk_summary,
        }


def _extract_external_domains(host_permissions: list[str], content_script_matches: list[str] | None = None) -> set[str]:
    """Extract unique external domains from permissions and content script matches."""
    domains: set[str] = set()
    all_patterns = list(host_permissions)
    if content_script_matches:
        all_patterns.extend(content_script_matches)

    for pattern in all_patterns:
        # Skip broad patterns
        if pattern in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*"):
            continue
        # Try to extract domain from match pattern or URL
        cleaned = pattern.replace("*://", "https://").replace("/*", "/")
        try:
            parsed = urlparse(cleaned)
            host = parsed.hostname
            if host:
                # Remove wildcard prefix
                host = host.lstrip("*").lstrip(".")
                if host and host not in _SAFE_DOMAINS:
                    # Check if any safe domain is a suffix
                    if not any(host.endswith("." + safe) or host == safe for safe in _SAFE_DOMAINS):
                        domains.add(host)
        except Exception:
            continue

    return domains


def _build_connectable_map(manifests: dict[str, dict]) -> dict[str, set[str]]:
    """Build adjacency list from externally_connectable declarations.

    Returns dict mapping ext_id -> set of extension IDs it declares as connectable.
    """
    adjacency: dict[str, set[str]] = {}
    for ext_id, manifest in manifests.items():
        ec = manifest.get("externally_connectable", {})
        if isinstance(ec, dict):
            ids = ec.get("ids", [])
            if isinstance(ids, list):
                adjacency[ext_id] = set(ids)
    return adjacency


def _get_web_accessible_resources(manifest: dict) -> list[str]:
    """Extract web_accessible_resources patterns from manifest."""
    war = manifest.get("web_accessible_resources", [])
    resources = []
    if isinstance(war, list):
        for entry in war:
            if isinstance(entry, str):
                resources.append(entry)
            elif isinstance(entry, dict):
                # MV3 format: {resources: [...], matches: [...]}
                resources.extend(entry.get("resources", []))
    return resources


def analyze_collusion(
    extensions_data: list[dict[str, Any]],
    manifests: dict[str, dict],
) -> CollusionReport:
    """Analyze cross-extension collusion risks.

    Args:
        extensions_data: List of extension metadata dicts from the companion extension.
        manifests: Dict mapping extension_id -> parsed manifest.json from CRX extraction.

    Returns:
        CollusionReport with detected collusion edges and summary.
    """
    if not extensions_data or not manifests:
        return CollusionReport()

    # Build lookup maps
    ext_names: dict[str, str] = {ext["id"]: ext.get("name", "Unknown") for ext in extensions_data}
    ext_permissions: dict[str, set[str]] = {
        ext["id"]: set(ext.get("permissions", []) + ext.get("hostPermissions", []))
        for ext in extensions_data
    }
    installed_ids = set(ext_names.keys())

    edges: list[CollusionEdge] = []
    affected: set[str] = set()

    # ── Check 1: externally_connectable ──────────────────
    connectable_map = _build_connectable_map(manifests)
    for source_id, connectable_ids in connectable_map.items():
        if source_id not in installed_ids:
            continue
        source_perms = ext_permissions.get(source_id, set())
        sensitive_source = source_perms & _SENSITIVE_PERMISSIONS

        for target_id in connectable_ids:
            if target_id not in installed_ids or target_id == source_id:
                continue
            if not sensitive_source:
                continue

            target_perms = ext_permissions.get(target_id, set())
            detail = (
                f"{ext_names.get(source_id, source_id)} declares {ext_names.get(target_id, target_id)} "
                f"as externally connectable. Source has sensitive permissions: {', '.join(sorted(sensitive_source))}. "
                f"Data could be forwarded between these extensions."
            )
            edges.append(CollusionEdge(
                source_id=source_id,
                source_name=ext_names.get(source_id, source_id),
                target_id=target_id,
                target_name=ext_names.get(target_id, target_id),
                risk_type="externally_connectable",
                detail=detail,
                severity="high" if len(sensitive_source) >= 2 else "medium",
            ))
            affected.add(source_id)
            affected.add(target_id)

    # ── Check 2: Shared external domains ─────────────────
    ext_domains: dict[str, set[str]] = {}
    for ext in extensions_data:
        ext_id = ext["id"]
        host_perms = ext.get("hostPermissions", [])
        manifest = manifests.get(ext_id, {})
        cs_matches = []
        for cs in manifest.get("content_scripts", []):
            cs_matches.extend(cs.get("matches", []))
        domains = _extract_external_domains(host_perms, cs_matches)
        if domains:
            ext_domains[ext_id] = domains

    # Find pairs with shared domains
    ext_ids_with_domains = list(ext_domains.keys())
    for i in range(len(ext_ids_with_domains)):
        for j in range(i + 1, len(ext_ids_with_domains)):
            id_a = ext_ids_with_domains[i]
            id_b = ext_ids_with_domains[j]
            shared = ext_domains[id_a] & ext_domains[id_b]
            if shared:
                detail = (
                    f"{ext_names.get(id_a, id_a)} and {ext_names.get(id_b, id_b)} "
                    f"both connect to: {', '.join(sorted(shared)[:5])}. "
                    f"Shared external domains could indicate a coordinated data pipeline."
                )
                edges.append(CollusionEdge(
                    source_id=id_a,
                    source_name=ext_names.get(id_a, id_a),
                    target_id=id_b,
                    target_name=ext_names.get(id_b, id_b),
                    risk_type="shared_domain",
                    detail=detail,
                    severity="medium",
                ))
                affected.add(id_a)
                affected.add(id_b)

    # ── Check 3: Permission chain ────────────────────────
    # A has cookies, B has webRequest to external domain → data pipeline
    for i in range(len(extensions_data)):
        for j in range(i + 1, len(extensions_data)):
            ext_a = extensions_data[i]
            ext_b = extensions_data[j]
            id_a, id_b = ext_a["id"], ext_b["id"]
            perms_a = set(ext_a.get("permissions", []))
            perms_b = set(ext_b.get("permissions", []))

            # Check A→B chain
            if "cookies" in perms_a and "webRequest" in perms_b:
                host_b = ext_b.get("hostPermissions", [])
                ext_domains_b = _extract_external_domains(host_b)
                if ext_domains_b:
                    detail = (
                        f"{ext_names.get(id_a, id_a)} has 'cookies' permission, "
                        f"{ext_names.get(id_b, id_b)} has 'webRequest' to {', '.join(sorted(ext_domains_b)[:3])}. "
                        f"Potential cookie exfiltration pipeline."
                    )
                    edges.append(CollusionEdge(
                        source_id=id_a,
                        source_name=ext_names.get(id_a, id_a),
                        target_id=id_b,
                        target_name=ext_names.get(id_b, id_b),
                        risk_type="permission_chain",
                        detail=detail,
                        severity="low",
                    ))
                    affected.add(id_a)
                    affected.add(id_b)

            # Check B→A chain
            if "cookies" in perms_b and "webRequest" in perms_a:
                host_a = ext_a.get("hostPermissions", [])
                ext_domains_a = _extract_external_domains(host_a)
                if ext_domains_a:
                    detail = (
                        f"{ext_names.get(id_b, id_b)} has 'cookies' permission, "
                        f"{ext_names.get(id_a, id_a)} has 'webRequest' to {', '.join(sorted(ext_domains_a)[:3])}. "
                        f"Potential cookie exfiltration pipeline."
                    )
                    edges.append(CollusionEdge(
                        source_id=id_b,
                        source_name=ext_names.get(id_b, id_b),
                        target_id=id_a,
                        target_name=ext_names.get(id_a, id_a),
                        risk_type="permission_chain",
                        detail=detail,
                        severity="low",
                    ))
                    affected.add(id_a)
                    affected.add(id_b)

    # Build summary
    if edges:
        risk_summary = f"Found {len(edges)} collusion risk{'s' if len(edges) != 1 else ''} across {len(affected)} extensions."
    else:
        risk_summary = "No cross-extension collusion risks detected."

    return CollusionReport(
        edges=edges,
        affected_extension_ids=affected,
        risk_summary=risk_summary,
    )
