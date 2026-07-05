"""ManifestGuard v4 — Live Threat Intel Burst.

Extracts domains/URLs/IPs from extension JavaScript source code and checks
them against external threat intelligence APIs (VirusTotal, AlienVault OTX,
URLScan.io) with strict 2-second timeouts.

Results are disk-cached for 24 hours to avoid API rate limits across scans.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────

ANOMALY_BOOST = 30      # Max anomaly score boost from intel burst findings
CACHE_TTL = 86400       # 24 hours
_CACHE_DIR = Path(__file__).resolve().parent / "data" / "intel_cache"

# Domains we never check — known safe infrastructure
_SAFELIST = {
    "google.com", "googleapis.com", "gstatic.com", "chrome.google.com",
    "mozilla.org", "github.com", "githubusercontent.com", "raw.githubusercontent.com",
    "cloudflare.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
    "unpkg.com", "jsdelivr.net", "npmjs.com", "npmjs.org",
    "facebook.com", "fb.com", "twitter.com", "x.com",
    "microsoft.com", "apple.com", "amazon.com", "amazonaws.com",
    "w3.org", "chromium.org", "googlesyndication.com",
    "googletagmanager.com", "google-analytics.com", "googleadservices.com",
    "youtube.com", "ytimg.com", "ggpht.com",
    "linkedin.com", "instagram.com", "reddit.com",
    "stackoverflow.com", "stackexchange.com",
    "sentry.io", "sentry-cdn.com",
    "stripe.com", "paypal.com",
    "fontawesome.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "bootstrapcdn.com", "jquery.com",
    "cloudfront.net", "akamaized.net", "fastly.net",
    "localhost", "127.0.0.1", "0.0.0.0",
}


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
        return {
            "domain": self.domain,
            "source": self.source,
            "isMalicious": self.is_malicious,
            "confidence": self.confidence,
            "detail": self.detail,
            "lastChecked": self.last_checked,
        }


@dataclass(slots=True)
class IntelBurstReport:
    """Summary of intel burst check."""

    results: list[DomainIntelResult] = field(default_factory=list)
    malicious_count: int = 0
    domains_checked: int = 0
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "results": [r.to_dict() for r in self.results],
            "maliciousCount": self.malicious_count,
            "domainsChecked": self.domains_checked,
            "timedOut": self.timed_out,
        }


# ── Domain extraction ──────────────────────────────────

def extract_domains_from_code(js_content: str) -> set[str]:
    """Extract unique domains from JavaScript source code.

    Uses regex to find URLs, bare domains, and IP addresses.
    Filters out safelisted domains. Returns max 50 domains.
    """
    domains: set[str] = set()

    # Find full URLs
    for match in re.finditer(r'https?://([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9])', js_content):
        host = match.group(1).lower().rstrip(".")
        if host and len(host) > 3:
            domains.add(host)

    # Find IP addresses (non-local) — block ALL private/reserved ranges
    for match in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', js_content):
        ip = match.group(1)
        # Block RFC1918, loopback, link-local, CGNAT, multicast, broadcast
        if ip.startswith(("127.", "192.168.", "10.", "0.", "169.254.", "224.", "255.")):
            continue
        # Block 172.16.0.0 – 172.31.255.255
        parts = ip.split(".")
        if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
            continue
        domains.add(ip)

    # Filter out safelisted
    filtered: set[str] = set()
    for domain in domains:
        if domain in _SAFELIST:
            continue
        if any(domain.endswith("." + safe) for safe in _SAFELIST):
            continue
        filtered.add(domain)

    # Cap at 50 to avoid API abuse
    return set(list(filtered)[:50])


# ── Disk cache ─────────────────────────────────────────

def _cache_path(domain: str) -> Path:
    h = hashlib.sha256(domain.encode()).hexdigest()[:16]
    return _CACHE_DIR / f"{h}.json"


def _read_cache(domain: str) -> list[DomainIntelResult] | None:
    path = _cache_path(domain)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - data.get("ts", 0) > CACHE_TTL:
            return None
        return [
            DomainIntelResult(
                domain=r["domain"], source=r["source"],
                is_malicious=r["isMalicious"], confidence=r["confidence"],
                detail=r["detail"], last_checked=r["lastChecked"],
            )
            for r in data.get("results", [])
        ]
    except Exception:
        return None


def _write_cache(domain: str, results: list[DomainIntelResult]) -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(domain)
    try:
        data = {
            "ts": time.time(),
            "results": [r.to_dict() for r in results],
        }
        path.write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass


# ── API checkers ───────────────────────────────────────

async def _check_virustotal(domain: str) -> DomainIntelResult | None:
    """Check domain against VirusTotal API v3."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return None

    try:
        import httpx
        # URL-encode domain to prevent injection
        safe_domain = httpx.URL(f"https://www.virustotal.com/api/v3/domains/{domain}").raw_path.decode()
        vt_url = f"https://www.virustotal.com{safe_domain}"
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(
                vt_url,
                headers={"x-apikey": api_key},
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 1
            confidence = malicious / max(total, 1)
            is_mal = malicious > 3

            return DomainIntelResult(
                domain=domain,
                source="virustotal",
                is_malicious=is_mal,
                confidence=round(confidence, 3),
                detail=f"VT: {malicious}/{total} engines flagged" if is_mal else f"VT: clean ({malicious}/{total})",
                last_checked=datetime.now(timezone.utc).isoformat(),
            )
    except Exception as e:
        log.debug("VirusTotal check failed for %s: %s", domain, e)
        return None


async def _check_alienvault_otx(domain: str) -> DomainIntelResult | None:
    """Check domain against AlienVault OTX."""
    api_key = os.environ.get("ALIENVAULT_OTX_KEY", "")
    if not api_key:
        return None

    try:
        import httpx
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": api_key},
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            is_mal = pulse_count > 0
            pulses = data.get("pulse_info", {}).get("pulses", [])
            pulse_names = [p.get("name", "Unknown") for p in pulses[:3]]

            return DomainIntelResult(
                domain=domain,
                source="alienvault_otx",
                is_malicious=is_mal,
                confidence=min(pulse_count / 10, 1.0) if is_mal else 0.0,
                detail=f"OTX: {pulse_count} pulses — {', '.join(pulse_names)}" if is_mal else "OTX: clean",
                last_checked=datetime.now(timezone.utc).isoformat(),
            )
    except Exception as e:
        log.debug("OTX check failed for %s: %s", domain, e)
        return None


async def _check_urlscan(domain: str) -> DomainIntelResult | None:
    """Check domain against URLScan.io."""
    api_key = os.environ.get("URLSCAN_API_KEY", "")
    if not api_key:
        return None

    try:
        import httpx
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1",
                headers={"API-Key": api_key},
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            results = data.get("results", [])
            is_mal = False
            for r in results:
                verdicts = r.get("verdicts", {})
                if verdicts.get("overall", {}).get("malicious"):
                    is_mal = True
                    break

            return DomainIntelResult(
                domain=domain,
                source="urlscan",
                is_malicious=is_mal,
                confidence=0.8 if is_mal else 0.0,
                detail=f"URLScan: flagged as malicious" if is_mal else "URLScan: clean",
                last_checked=datetime.now(timezone.utc).isoformat(),
            )
    except Exception as e:
        log.debug("URLScan check failed for %s: %s", domain, e)
        return None


async def _check_domain(domain: str) -> list[DomainIntelResult]:
    """Run all 3 threat intel checks concurrently for a single domain."""
    # Check cache first
    cached = _read_cache(domain)
    if cached is not None:
        return cached

    tasks = [
        _check_virustotal(domain),
        _check_alienvault_otx(domain),
        _check_urlscan(domain),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    valid: list[DomainIntelResult] = []
    for r in results:
        if isinstance(r, DomainIntelResult):
            valid.append(r)

    # Cache results
    _write_cache(domain, valid)
    return valid


async def burst_check_domains(domains: set[str], timeout: float = 2.0) -> IntelBurstReport:
    """Check up to 10 domains concurrently against threat intel APIs.

    Uses asyncio with strict timeout. Returns partial results if timeout hits.
    """
    report = IntelBurstReport(domains_checked=0)

    # Limit to 10 domains (prioritize shorter/non-standard ones)
    sorted_domains = sorted(domains, key=lambda d: (len(d), d))[:10]

    if not sorted_domains:
        return report

    try:
        async def check_all():
            tasks = [_check_domain(d) for d in sorted_domains]
            return await asyncio.gather(*tasks, return_exceptions=True)

        raw_results = await asyncio.wait_for(check_all(), timeout=timeout)
        report.domains_checked = len(sorted_domains)

        for result in raw_results:
            if isinstance(result, list):
                report.results.extend(result)
            # Exceptions are silently ignored

    except asyncio.TimeoutError:
        report.timed_out = True
        log.debug("Intel burst timed out after %.1fs", timeout)

    report.malicious_count = sum(1 for r in report.results if r.is_malicious)
    return report


def burst_check_domains_sync(domains: set[str], timeout: float = 2.0) -> IntelBurstReport:
    """Synchronous wrapper for burst_check_domains.

    Creates a new event loop if needed (safe for FastAPI sync endpoints).
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already in an async context — run in a new thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, burst_check_domains(domains, timeout))
            return future.result(timeout=timeout + 1)
    else:
        return asyncio.run(burst_check_domains(domains, timeout))


def compute_anomaly_boost(report: IntelBurstReport) -> int:
    """Compute anomaly score boost from intel burst results.

    Returns 0 if no malicious domains found.
    Capped at ANOMALY_BOOST (30).
    """
    if report.malicious_count <= 0:
        return 0
    return min(report.malicious_count * 15, ANOMALY_BOOST)
