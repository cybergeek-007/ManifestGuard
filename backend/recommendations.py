"""Safe alternative recommendation engine.

When an extension is flagged as suspicious, moderate_risk, or known_malicious,
this module suggests trusted alternatives from the allowlist that serve the
same purpose.

Uses a hybrid approach:
1. Permission-similarity scoring (weighted Jaccard index)
2. Keyword-based category matching
3. Falls back gracefully when no good matches exist
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


# ── Category keyword mapping ────────────────────────────────
CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "password_manager": [
        "password", "vault", "login", "credential", "autofill", "passkey",
        "keychain", "keeper", "bitwarden", "lastpass", "dashlane",
    ],
    "ad_blocker": [
        "ad block", "adblock", "ad-block", "adblocker", "tracker blocker",
        "anti-track", "content blocker", "ad guard", "adguard",
    ],
    "privacy_tool": [
        "privacy", "vpn", "proxy", "encrypt", "anonymous", "do not track",
        "anti-fingerprint", "incognito", "private browsing",
    ],
    "developer_tool": [
        "devtools", "developer tool", "debug", "inspector", "react dev",
        "vue dev", "redux", "json viewer", "web developer", "lighthouse",
        "postman", "api test", "css", "html", "code",
    ],
    "security_tool": [
        "security", "antivirus", "malware", "phishing", "guard", "protect",
        "safe browsing", "threat", "firewall",
    ],
    "productivity": [
        "grammar", "translate", "todoist", "notion", "evernote", "clipboard",
        "tab manager", "bookmark", "notes", "timer", "pomodoro", "calendar",
        "task", "trello", "asana",
    ],
    "communication": [
        "zoom", "slack", "teams", "meet", "chat", "messenger", "discord",
        "telegram", "whatsapp", "video call", "conference",
    ],
    "shopping": [
        "coupon", "cashback", "price", "deal", "shopping", "honey",
        "discount", "compare", "rakuten", "capital one",
    ],
    "accessibility": [
        "dark mode", "dark reader", "high contrast", "screen reader",
        "text to speech", "dyslexia", "zoom", "magnif", "accessibility",
        "color blind",
    ],
    "media": [
        "youtube", "video", "spotify", "music", "picture in picture",
        "pip", "volume", "shazam", "media", "stream", "netflix",
    ],
    "education": [
        "citation", "reference", "zotero", "mendeley", "scholar",
        "research", "academic", "bibliography", "study",
    ],
    "ai_tool": [
        "chatgpt", "ai", "gpt", "copilot", "artificial intelligence",
        "machine learning", "writing assistant", "ai writer",
    ],
    "download_manager": [
        "download", "save video", "video download", "download manager",
        "save as", "file download",
    ],
    "screenshot_capture": [
        "screenshot", "screen capture", "screen record", "screencast",
        "snip", "full page capture", "clip", "snapshot", "capture",
        "web clip", "clone", "save page",
    ],
    "web_design": [
        "design", "css", "color picker", "font", "inspect", "wireframe",
        "prototype", "figma", "sketch", "layout", "responsive", "clone",
        "element", "web design",
    ],
}

# Permission groups that indicate functional similarity
_PERMISSION_GROUPS: dict[str, set[str]] = {
    "web_access": {"<all_urls>", "http://*/*", "https://*/*", "activeTab", "tabs"},
    "data_capture": {"clipboardRead", "clipboardWrite", "downloads"},
    "page_modify": {"scripting", "declarativeContent", "contentSettings"},
    "browsing_data": {"history", "bookmarks", "topSites", "sessions"},
    "identity": {"identity", "cookies", "webRequest", "webRequestBlocking"},
    "system": {"management", "nativeMessaging", "processes", "system.cpu"},
    "storage": {"storage", "unlimitedStorage"},
    "notifications": {"notifications", "alarms"},
}


@dataclass(slots=True)
class Recommendation:
    """A safe alternative extension recommendation."""

    name: str
    extension_id: str
    publisher: str
    category: str
    users: str
    rating: float
    reason: str
    install_url: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def infer_category(name: str, description: str = "") -> str:
    """Infer the category of an extension from its name and description.

    Returns the most likely category string, or 'uncategorized'.
    """
    text = f"{name} {description}".lower()

    best_category = "uncategorized"
    best_score = 0

    for category, keywords in CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > best_score:
            best_score = score
            best_category = category

    return best_category


def _compute_permission_similarity(
    perms_a: set[str], perms_b: set[str]
) -> float:
    """Compute weighted Jaccard similarity between two permission sets.

    Returns 0.0 to 1.0. Weights 'dangerous' permissions higher.
    """
    if not perms_a and not perms_b:
        return 0.0

    # High-weight permissions (these strongly indicate purpose)
    high_weight = {
        "<all_urls>", "http://*/*", "https://*/*", "tabs", "activeTab",
        "webRequest", "webRequestBlocking", "cookies", "history",
        "downloads", "clipboardRead", "clipboardWrite", "management",
        "scripting", "nativeMessaging", "identity", "proxy",
        "declarativeNetRequest",
    }

    def weighted_set(perms: set[str]) -> dict[str, float]:
        return {p: (2.0 if p in high_weight else 1.0) for p in perms}

    wa = weighted_set(perms_a)
    wb = weighted_set(perms_b)

    all_perms = set(wa) | set(wb)
    if not all_perms:
        return 0.0

    intersection_score = sum(
        min(wa.get(p, 0), wb.get(p, 0)) for p in all_perms
    )
    union_score = sum(
        max(wa.get(p, 0), wb.get(p, 0)) for p in all_perms
    )

    return intersection_score / union_score if union_score > 0 else 0.0


def _compute_group_similarity(
    perms_a: set[str], perms_b: set[str]
) -> float:
    """Check how many permission groups overlap between two extensions."""
    def get_groups(perms: set[str]) -> set[str]:
        groups = set()
        for group_name, group_perms in _PERMISSION_GROUPS.items():
            if perms & group_perms:
                groups.add(group_name)
        return groups

    groups_a = get_groups(perms_a)
    groups_b = get_groups(perms_b)

    if not groups_a and not groups_b:
        return 0.0
    if not groups_a or not groups_b:
        return 0.0

    intersection = groups_a & groups_b
    union = groups_a | groups_b
    return len(intersection) / len(union)


def get_recommendations(
    extension_name: str,
    extension_description: str,
    category: str | None = None,
    max_results: int = 3,
    permissions: list[str] | None = None,
    host_permissions: list[str] | None = None,
) -> list[Recommendation]:
    """Get safe alternative recommendations for a flagged extension.

    Uses a hybrid scoring approach:
    1. Category match score (keyword-based)
    2. Permission similarity score (weighted Jaccard)
    3. Permission group overlap score

    Only recommends if combined confidence is above threshold.
    """
    from backend.allowlist import TRUSTED_EXTENSIONS, get_alternatives_for_category

    # Infer category if not provided
    if not category:
        category = infer_category(extension_name, extension_description)

    # Build the scanned extension's permission set
    ext_perms = set(permissions or []) | set(host_permissions or [])

    # Score every trusted extension
    scored: list[tuple[float, Any]] = []

    for entry in TRUSTED_EXTENSIONS.values():
        score = 0.0
        reasons: list[str] = []

        # 1. Category match (0 or 0.4)
        entry_category = entry.category
        if category != "uncategorized" and (
            entry_category == category or category in entry.safe_alternative_for
        ):
            score += 0.4
            reasons.append(f"Same category ({category.replace('_', ' ')})")

        # 2. Name/description keyword overlap
        ext_text = f"{extension_name} {extension_description}".lower()
        entry_text = f"{entry.name} {entry.reason_trusted}".lower()
        ext_words = set(ext_text.split()) - {"the", "a", "an", "and", "or", "for", "to", "in", "of", "is", "it", "with"}
        entry_words = set(entry_text.split()) - {"the", "a", "an", "and", "or", "for", "to", "in", "of", "is", "it", "with"}
        word_overlap = len(ext_words & entry_words)
        if word_overlap >= 2:
            score += min(word_overlap * 0.05, 0.2)

        # 3. Permission similarity (0 to 0.3)
        if ext_perms:
            # Build entry's typical permissions from its category
            entry_perms = _get_typical_permissions_for_category(entry_category)
            perm_sim = _compute_permission_similarity(ext_perms, entry_perms)
            score += perm_sim * 0.3

            # 4. Permission group overlap (0 to 0.2)
            group_sim = _compute_group_similarity(ext_perms, entry_perms)
            score += group_sim * 0.2

        if score >= 0.15:
            scored.append((score, entry, reasons))

    # Sort by score descending
    scored.sort(key=lambda x: -x[0])

    # Build recommendations from top results
    recommendations: list[Recommendation] = []
    seen_ids: set[str] = set()

    for _score, entry, reasons in scored[:max_results * 2]:
        if entry.extension_id in seen_ids:
            continue
        seen_ids.add(entry.extension_id)

        reason = entry.reason_trusted
        if reasons:
            reason = reasons[0]

        rec = Recommendation(
            name=entry.name,
            extension_id=entry.extension_id,
            publisher=entry.publisher,
            category=entry.category,
            users="",
            rating=0.0,
            reason=reason,
            install_url=f"https://chromewebstore.google.com/detail/{entry.extension_id}",
        )
        recommendations.append(rec)
        if len(recommendations) >= max_results:
            break

    # If no good matches, fall back to category-based but with a notice
    if not recommendations and category != "uncategorized":
        alternatives = get_alternatives_for_category(category)
        for entry in alternatives[:max_results]:
            rec = Recommendation(
                name=entry.name,
                extension_id=entry.extension_id,
                publisher=entry.publisher,
                category=entry.category,
                users="",
                rating=0.0,
                reason=entry.reason_trusted,
                install_url=f"https://chromewebstore.google.com/detail/{entry.extension_id}",
            )
            recommendations.append(rec)

    return recommendations


def _get_typical_permissions_for_category(category: str) -> set[str]:
    """Return a typical permission set for extensions in a given category.

    Used to compare the scanned extension's permissions against what
    trusted alternatives in each category typically need.
    """
    _CATEGORY_PERMS: dict[str, set[str]] = {
        "password_manager": {"storage", "activeTab", "clipboardWrite", "clipboardRead", "identity"},
        "ad_blocker": {"<all_urls>", "webRequest", "webRequestBlocking", "storage", "tabs", "declarativeNetRequest"},
        "privacy_tool": {"<all_urls>", "webRequest", "webRequestBlocking", "proxy", "storage", "cookies"},
        "developer_tool": {"activeTab", "tabs", "storage", "scripting", "devtools", "contextMenus"},
        "security_tool": {"<all_urls>", "webRequest", "storage", "tabs", "notifications"},
        "productivity": {"activeTab", "storage", "tabs", "contextMenus", "notifications"},
        "communication": {"notifications", "storage", "tabs", "identity"},
        "shopping": {"activeTab", "storage", "tabs", "<all_urls>"},
        "accessibility": {"activeTab", "storage", "tabs", "<all_urls>"},
        "media": {"activeTab", "storage", "tabs"},
        "education": {"activeTab", "storage", "contextMenus"},
        "ai_tool": {"activeTab", "storage", "tabs", "contextMenus"},
        "download_manager": {"downloads", "activeTab", "storage", "tabs", "<all_urls>"},
        "screenshot_capture": {"activeTab", "tabs", "storage", "<all_urls>", "clipboardWrite", "downloads"},
        "web_design": {"activeTab", "tabs", "storage", "<all_urls>", "scripting", "clipboardWrite"},
    }
    return _CATEGORY_PERMS.get(category, {"storage", "activeTab"})
