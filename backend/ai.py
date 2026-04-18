from __future__ import annotations

import os
from typing import Iterable

from backend.models import ExtensionFinding

try:  # pragma: no cover - optional dependency
    from openai import OpenAI
except ImportError:  # pragma: no cover - optional dependency
    OpenAI = None  # type: ignore[assignment]


def _api_key() -> str:
    return (
        os.getenv("MANIFESTGUARD_AI_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or os.getenv("groq_api_key")
        or ""
    )


def _base_url() -> str | None:
    return os.getenv("MANIFESTGUARD_AI_BASE_URL") or os.getenv("OPENAI_BASE_URL") or os.getenv("GROQ_BASE_URL")


def _model_name() -> str:
    return os.getenv("MANIFESTGUARD_AI_MODEL", "gpt-4o-mini")


def build_ai_summary(finding: ExtensionFinding) -> str | None:
    if OpenAI is None:
        return None
    api_key = _api_key()
    if not api_key:
        return None

    client_kwargs = {"api_key": api_key}
    base_url = _base_url()
    if base_url:
        client_kwargs["base_url"] = base_url
    client = OpenAI(**client_kwargs)

    signal_lines = "\n".join(
        f"- {signal.title}: {signal.detail}" for signal in finding.suspicious_signals[:8]
    ) or "- No suspicious signals detected."
    intel_lines = "\n".join(
        f"- {match.label}: {match.detail}" for match in finding.intel_matches[:5]
    ) or "- No curated threat-intel matches."

    prompt = f"""
You are assisting with a local browser-extension audit.
Explain the classification without changing the deterministic verdict.

Extension: {finding.name}
ID: {finding.id}
Version: {finding.version}
Verdict: {finding.verdict}
Power score: {finding.power_score}
Suspicion score: {finding.suspicion_score}
Store status: {finding.store_status}
Permissions: {", ".join(finding.permissions) or "none"}
Host permissions: {", ".join(finding.host_permissions) or "none"}

Suspicious signals:
{signal_lines}

Intel matches:
{intel_lines}

Write 3 short sections:
1. Why it was classified this way
2. What the user should pay attention to
3. Suggested next step

Be concise, balanced, and specific.
""".strip()

    try:  # pragma: no cover - network dependent
        response = client.chat.completions.create(
            model=_model_name(),
            temperature=0.2,
            messages=[
                {"role": "system", "content": "You are a precise cybersecurity analyst."},
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
