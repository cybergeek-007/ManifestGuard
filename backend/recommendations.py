"""Safe alternative recommendation engine.

When an extension is flagged as suspicious, moderate_risk, or known_malicious,
this module suggests trusted alternatives from the allowlist that serve the
same purpose.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# ── Category keyword mapping ────────────────────────────────
# Maps keywords found in extension names/descriptions to categories.
# Used to infer what an unknown extension does so we can recommend
# alternatives from the same category.
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
        "postman", "api test",
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
        "snip", "full page capture",
    ],
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

    # Score each category by keyword matches
    best_category = "uncategorized"
    best_score = 0

    for category, keywords in CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > best_score:
            best_score = score
            best_category = category

    return best_category


def get_recommendations(
    extension_name: str,
    extension_description: str,
    category: str | None = None,
    max_results: int = 3,
) -> list[Recommendation]:
    """Get safe alternative recommendations for a flagged extension.

    If category is not provided, it's inferred from the name/description.
    Returns up to max_results recommendations from the allowlist.
    """
    # Import here to avoid circular imports
    from backend.allowlist import get_alternatives_for_category, lookup_allowlist

    if not category:
        category = infer_category(extension_name, extension_description)

    if category == "uncategorized":
        # Try harder — check if the name/description hints at a function
        # If still nothing, return general popular extensions
        category = _fallback_category(extension_name, extension_description)

    alternatives = get_alternatives_for_category(category)

    recommendations: list[Recommendation] = []
    for entry in alternatives[:max_results]:
        rec = Recommendation(
            name=entry.name,
            extension_id=entry.extension_id,
            publisher=entry.publisher,
            category=entry.category,
            users="",  # Populated from reputation data if available
            rating=0.0,
            reason=entry.reason_trusted,
            install_url=f"https://chromewebstore.google.com/detail/{entry.extension_id}",
        )
        recommendations.append(rec)

    return recommendations


def enrich_recommendations_with_reputation(
    recommendations: list[Recommendation],
) -> list[Recommendation]:
    """Enrich recommendations with reputation data (user count, rating).

    This is called after reputation data has been fetched to fill in
    the dynamic fields.
    """
    from backend.reputation import fetch_reputation

    for rec in recommendations:
        try:
            rep = fetch_reputation(rec.extension_id)
            if rep.lookup_status == "success":
                rec.users = rep.user_count_display or f"{rep.user_count:,}+ users"
                rec.rating = rep.star_rating
        except Exception:
            pass

    return recommendations


def _fallback_category(name: str, description: str) -> str:
    """Fallback category inference for truly uncategorized extensions."""
    text = f"{name} {description}".lower()

    # Check for permission-like clues
    if any(w in text for w in ["new tab", "homepage", "start page", "wallpaper"]):
        return "productivity"
    if any(w in text for w in ["email", "mail", "inbox"]):
        return "communication"
    if any(w in text for w in ["image", "photo", "picture", "gallery"]):
        return "media"
    if any(w in text for w in ["code", "github", "git", "programming"]):
        return "developer_tool"

    return "uncategorized"
