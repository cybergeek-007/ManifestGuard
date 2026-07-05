"""Chrome Web Store reputation engine.

Fetches extension metadata (user count, ratings, publisher badges) from the
Chrome Web Store detail page and computes a 0-100 reputation score.  Results
are cached in memory and to disk with a configurable TTL.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# ── Cache settings ───────────────────────────────────────────────────
_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours
_MAX_MEMORY_CACHE = 500  # Evict oldest entries beyond this
_CACHE_DIR = Path(__file__).resolve().parent / "data" / "reputation_cache"
_MEMORY_CACHE: dict[str, tuple[float, "ReputationResult"]] = {}
_CACHE_LOCK = threading.Lock()

CWS_DETAIL_URL = "https://chromewebstore.google.com/detail/{extension_id}"


# ── Data classes ─────────────────────────────────────────────


@dataclass(slots=True)
class ReputationResult:
    """Parsed Chrome Web Store metadata for a single extension."""

    extension_id: str
    user_count: int = 0
    user_count_display: str = ""
    star_rating: float = 0.0
    review_count: int = 0
    last_updated: str = ""
    developer_name: str = ""
    is_featured: bool = False
    is_established_publisher: bool = False
    reputation_score: int = 0
    lookup_status: str = "unknown"  # "success" | "not_found" | "error" | "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ReputationResult:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── Reputation score calculation ─────────────────────────────


def _compute_reputation_score(r: ReputationResult) -> int:
    """Compute a 0-100 reputation score from CWS metadata signals."""
    score = 0

    # User count (0-30 points)
    if r.user_count >= 1_000_000:
        score += 30
    elif r.user_count >= 100_000:
        score += 25
    elif r.user_count >= 10_000:
        score += 20
    elif r.user_count >= 1_000:
        score += 10
    elif r.user_count >= 100:
        score += 5

    # Star rating (0-20 points)
    if r.star_rating >= 4.5:
        score += 20
    elif r.star_rating >= 4.0:
        score += 15
    elif r.star_rating >= 3.5:
        score += 10
    elif r.star_rating >= 3.0:
        score += 5

    # Publisher badge (0-25 points)
    if r.is_featured:
        score += 25
    elif r.is_established_publisher:
        score += 15

    # Store age / freshness — we use last_updated as a proxy (0-15 points)
    # If updated recently, the developer is actively maintaining it
    if r.last_updated:
        try:
            from datetime import datetime

            updated = datetime.strptime(r.last_updated, "%Y-%m-%d")
            days_since = (datetime.now() - updated).days
            if days_since <= 90:
                score += 15
            elif days_since <= 180:
                score += 10
            elif days_since <= 365:
                score += 5
            # > 1 year stale = 0 points
        except (ValueError, TypeError):
            pass

    # Review volume bonus (0-10 points)
    if r.review_count >= 10_000:
        score += 10
    elif r.review_count >= 1_000:
        score += 7
    elif r.review_count >= 100:
        score += 4
    elif r.review_count >= 10:
        score += 2

    return min(score, 100)


# ── CWS page scraping ───────────────────────────────────────


def _parse_user_count(text: str) -> tuple[int, str]:
    """Extract user count from CWS page text like '10,000,000+ users'."""
    match = re.search(r'([\d,]+)\+?\s*users', text, re.IGNORECASE)
    if match:
        display = match.group(0)
        count = int(match.group(1).replace(",", ""))
        return count, display
    # Try alternate format "10M users"
    match = re.search(r'([\d.]+)\s*([KMB])\+?\s*users', text, re.IGNORECASE)
    if match:
        num = float(match.group(1))
        suffix = match.group(2).upper()
        multiplier = {"K": 1_000, "M": 1_000_000, "B": 1_000_000_000}.get(suffix, 1)
        count = int(num * multiplier)
        return count, match.group(0)
    return 0, ""


def _parse_rating(text: str) -> tuple[float, int]:
    """Extract star rating and review count."""
    # Look for rating pattern like "4.5" near "stars" or "rating"
    rating = 0.0
    reviews = 0
    # Pattern: "4.5 out of 5" or just a standalone rating
    rating_match = re.search(r'(\d+\.?\d*)\s*(?:out of 5|stars?|/5)', text, re.IGNORECASE)
    if rating_match:
        rating = float(rating_match.group(1))
    else:
        # Try to find JSON-LD or structured data
        rating_match = re.search(r'"ratingValue"\s*:\s*"?(\d+\.?\d*)"?', text)
        if rating_match:
            rating = float(rating_match.group(1))

    # Review count
    review_match = re.search(r'"ratingCount"\s*:\s*"?(\d+)"?', text)
    if review_match:
        reviews = int(review_match.group(1))
    else:
        review_match = re.search(r'([\d,]+)\s*(?:reviews?|ratings?)', text, re.IGNORECASE)
        if review_match:
            reviews = int(review_match.group(1).replace(",", ""))

    return rating, reviews


def _parse_developer(text: str) -> str:
    """Extract developer name."""
    # Look for "Offered by: DeveloperName" or "by DeveloperName"
    match = re.search(r'(?:Offered by|by)\s*:?\s*([A-Za-z0-9\s.,&\'-]+?)(?:\s*\n|\s*<|\s*$)', text)
    if match:
        return match.group(1).strip()
    # Try structured data
    match = re.search(r'"author"\s*:\s*\{[^}]*"name"\s*:\s*"([^"]+)"', text)
    if match:
        return match.group(1)
    return ""


def _parse_last_updated(text: str) -> str:
    """Extract last updated date."""
    # Look for "Updated: January 15, 2025" or similar
    match = re.search(
        r'(?:Updated|Last updated)\s*:?\s*(\w+ \d{1,2},?\s*\d{4})', text, re.IGNORECASE
    )
    if match:
        raw = match.group(1)
        try:
            from datetime import datetime

            for fmt in ("%B %d, %Y", "%B %d %Y", "%b %d, %Y", "%b %d %Y"):
                try:
                    dt = datetime.strptime(raw, fmt)
                    return dt.strftime("%Y-%m-%d")
                except ValueError:
                    continue
        except Exception:
            pass
    # Try ISO date
    match = re.search(r'"dateModified"\s*:\s*"(\d{4}-\d{2}-\d{2})', text)
    if match:
        return match.group(1)
    return ""


def _check_publisher_badges(text: str) -> tuple[bool, bool]:
    # Use stricter matching to avoid false positives on words like "Features" or plain text
    is_featured = bool(re.search(r'aria-label=[\'"]Featured[\'"]|>Featured<', text, re.IGNORECASE))
    is_established = bool(
        re.search(r'aria-label=[\'"](?:Established|Verified) Publisher[\'"]|>(?:Established|Verified) Publisher<', text, re.IGNORECASE)
    )
    return is_featured, is_established


def _scrape_cws_page(extension_id: str, timeout: float = 6.0) -> ReputationResult:
    """Scrape the Chrome Web Store detail page for extension metadata."""
    result = ReputationResult(extension_id=extension_id)
    url = CWS_DETAIL_URL.format(extension_id=extension_id)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }

    request = urllib.request.Request(url, headers=headers)
    context = ssl.create_default_context()

    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            result.lookup_status = "not_found"
        else:
            result.lookup_status = "error"
        return result
    except Exception:
        result.lookup_status = "error"
        return result

    # Parse the page
    result.user_count, result.user_count_display = _parse_user_count(body)
    result.star_rating, result.review_count = _parse_rating(body)
    result.developer_name = _parse_developer(body)
    result.last_updated = _parse_last_updated(body)
    result.is_featured, result.is_established_publisher = _check_publisher_badges(body)
    result.lookup_status = "success"
    result.reputation_score = _compute_reputation_score(result)

    return result


# ── Caching layer ────────────────────────────────────────────


def _cache_path(extension_id: str) -> Path:
    # Hash the ID to prevent path traversal — never use raw user input in paths
    safe_name = hashlib.sha256(extension_id.encode()).hexdigest()[:24]
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return _CACHE_DIR / f"{safe_name}.json"


def _read_disk_cache(extension_id: str) -> ReputationResult | None:
    path = _cache_path(extension_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        cached_at = data.get("_cached_at", 0)
        if time.time() - cached_at > _CACHE_TTL_SECONDS:
            return None
        return ReputationResult.from_dict(data)
    except Exception:
        return None


def _write_disk_cache(result: ReputationResult) -> None:
    try:
        path = _cache_path(result.extension_id)
        data = result.to_dict()
        data["_cached_at"] = time.time()
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


# ── Public API ───────────────────────────────────────────────


def fetch_reputation(extension_id: str, use_cache: bool = True) -> ReputationResult:
    """Fetch reputation data for an extension, with caching.

    Returns a ReputationResult with a 0-100 reputation_score.
    """
    # Check memory cache
    with _CACHE_LOCK:
        if use_cache and extension_id in _MEMORY_CACHE:
            cached_at, result = _MEMORY_CACHE[extension_id]
            if time.time() - cached_at < _CACHE_TTL_SECONDS:
                return result

    # Check disk cache
    if use_cache:
        disk_result = _read_disk_cache(extension_id)
        if disk_result:
            with _CACHE_LOCK:
                _MEMORY_CACHE[extension_id] = (time.time(), disk_result)
            return disk_result

    # Scrape CWS
    result = _scrape_cws_page(extension_id)

    # Cache results (even failures, to avoid hammering CWS)
    with _CACHE_LOCK:
        if len(_MEMORY_CACHE) >= _MAX_MEMORY_CACHE:
            oldest_key = min(_MEMORY_CACHE, key=lambda k: _MEMORY_CACHE[k][0])
            del _MEMORY_CACHE[oldest_key]
        _MEMORY_CACHE[extension_id] = (time.time(), result)
    if result.lookup_status != "error":
        _write_disk_cache(result)

    return result


def compute_reputation_adjustment(reputation_score: int) -> float:
    """Compute the suspicion adjustment factor based on reputation.

    Returns a multiplier for the suspicion score:
    - We cap the reduction at 0.50 (50% reduction) to ensure supply-chain attacks 
      on highly popular extensions are still caught if they exhibit anomalous behavior.
    """
    if reputation_score >= 80:
        return 0.50
    if reputation_score >= 70:
        return 0.60
    if reputation_score >= 60:
        return 0.70
    if reputation_score >= 40:
        return 0.85
    if reputation_score >= 20:
        return 1.10
    return 1.25


def batch_fetch_reputation(
    extension_ids: list[str], use_cache: bool = True
) -> dict[str, ReputationResult]:
    """Fetch reputation for multiple extensions.

    Note: CWS scraping is rate-limited, so this is sequential with a small delay.
    """
    results: dict[str, ReputationResult] = {}
    for ext_id in extension_ids:
        results[ext_id] = fetch_reputation(ext_id, use_cache=use_cache)
        # Small delay to avoid rate limiting
        import time as _t
        _t.sleep(0.3)
    return results
