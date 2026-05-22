from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from backend.models import ExtensionFinding

try:  # pragma: no cover - optional dependency
    from openai import OpenAI
except ImportError:  # pragma: no cover - optional dependency
    OpenAI = None  # type: ignore[assignment]

# ── Load .env file if it exists ─────────────────────────────
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    try:
        for line in _env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("\"'")
            if key and value and key not in os.environ:
                os.environ[key] = value
    except Exception:
        pass


def _api_key() -> str:
    return (
        os.getenv("GROQ_API_KEY")
        or os.getenv("MANIFESTGUARD_AI_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or os.getenv("groq_api_key")
        or ""
    )


def _base_url() -> str:
    return (
        os.getenv("MANIFESTGUARD_AI_BASE_URL")
        or os.getenv("GROQ_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or "https://api.groq.com/openai/v1"
    )


def _model_name() -> str:
    return os.getenv("MANIFESTGUARD_AI_MODEL", "llama-3.3-70b-versatile")


def build_ai_summary(finding: ExtensionFinding) -> str | None:
    if OpenAI is None:
        return None
    api_key = _api_key()
    if not api_key:
        return None

    client = OpenAI(api_key=api_key, base_url=_base_url())

    signal_lines = "\n".join(
        f"- [{signal.severity}/35] {signal.title}: {signal.detail}" for signal in finding.suspicious_signals[:8]
    ) or "- No suspicious signals detected."
    intel_lines = "\n".join(
        f"- [{match.confidence}] {match.label}: {match.detail}" for match in finding.intel_matches[:5]
    ) or "- No curated threat-intel matches."

    perm_context = ""
    if finding.permissions:
        perm_context = f"\nPermissions ({len(finding.permissions)}): {', '.join(finding.permissions[:15])}"
    if finding.host_permissions:
        perm_context += f"\nHost permissions: {', '.join(finding.host_permissions[:10])}"

    prompt = f"""You are a senior cybersecurity analyst reviewing a browser extension for an enterprise security audit.
Write a natural, conversational, yet highly professional assessment of this extension.

Extension Data:
Name: {finding.name} (ID: {finding.id})
Version: {finding.version}
Category: {finding.category or 'Unknown'}
Verdict: {finding.verdict}
Reputation Score (Trust): {finding.reputation_score if finding.reputation_score is not None else 'Unknown'}/100
Suspicion Score (Code Risk): {finding.suspicion_score}/100
Power Score (Reach): {finding.power_score}/100
Store Status: {finding.store_status}
{perm_context}

Suspicious Signals Found:
{signal_lines}

Threat Intelligence:
{intel_lines}

Your task is to write a 2-3 paragraph executive summary that sounds like a real analyst speaking directly to the user.

- Paragraph 1: Give your bottom-line assessment. Is this a trusted tool with a stellar reputation, a powerful but expected utility, or a highly suspicious piece of software? Mention its store reputation and category.
- Paragraph 2: Discuss the technical findings. If there are suspicious signals (like remote code execution or credential harvesting), explain why they matter in plain English. If it's a safe tool with high permissions (like an ad blocker), reassure the user that these permissions are normal for its function.
- Paragraph 3: Give a definitive, clear recommendation (e.g., "I recommend keeping this extension as it is highly trusted...", "You should remove this immediately due to severe risk indicators...", or "Consider replacing this with a safer alternative...").

Do NOT use robotic formatting like "1. Risk Summary:" or excessive markdown bullet points. Write natural, flowing paragraphs. Sound confident, insightful, and authoritative.""".strip()

    try:  # pragma: no cover - network dependent
        response = client.chat.completions.create(
            model=_model_name(),
            temperature=0.3,
            max_tokens=400,
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity analyst. You speak directly to users, offering insightful, natural, and authoritative security assessments of browser extensions. Do not use generic markdown lists; write fluid, compelling paragraphs."},
                {"role": "user", "content": prompt},
            ],
        )
    except Exception:
        return None

    return response.choices[0].message.content if response.choices else None


def maybe_enrich_with_ai(findings: Iterable[ExtensionFinding], enabled: bool) -> None:
    if not enabled:
        return
    for finding in findings:
        finding.ai_summary = build_ai_summary(finding)
