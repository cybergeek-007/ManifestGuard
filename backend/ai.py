from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
from pathlib import Path
from typing import Any, Iterable

from backend.models import ExtensionFinding

log = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    from openai import OpenAI
except ImportError:  # pragma: no cover - optional dependency
    OpenAI = None  # type: ignore[assignment]

# ── Load .env file if it exists ─────────────────────────────
_env_path = Path(__file__).resolve().parent / ".env"
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


# ── Provider presets (all OpenAI-compatible) ─────────────────
PROVIDER_PRESETS: dict[str, dict[str, str]] = {
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "default_model": "gemini-2.0-flash",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "meta-llama/llama-3.3-70b-instruct",
    },
    "together": {
        "base_url": "https://api.together.xyz/v1",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "default_model": "mistral-large-latest",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
    },
    "huggingface": {
        "base_url": "https://api-inference.huggingface.co/v1/",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct",
    },
    "xai": {
        "base_url": "https://api.x.ai/v1",
        "default_model": "grok-3-mini-fast",
    },
    "cerebras": {
        "base_url": "https://api.cerebras.ai/v1",
        "default_model": "llama-3.3-70b",
    },
    "sambanova": {
        "base_url": "https://api.sambanova.ai/v1",
        "default_model": "Meta-Llama-3.3-70B-Instruct",
    },
}


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


def _make_client(ai_config: dict[str, str] | None = None):
    """Create an OpenAI-compatible client.

    If `ai_config` is provided (from user request headers), uses that config.
    Otherwise falls back to server .env variables.
    Returns (client, model_name) tuple, or (None, None) if unavailable.
    """
    if OpenAI is None:
        return None, None

    if ai_config and ai_config.get("api_key"):
        # User-provided config
        provider = ai_config.get("provider", "custom")
        api_key = ai_config["api_key"]
        preset = PROVIDER_PRESETS.get(provider, {})

        base_url = ai_config.get("base_url") or preset.get("base_url", "")
        # Cloudflare needs account_id injected into URL
        account_id = ai_config.get("account_id", "")
        if provider == "cloudflare" and account_id:
            base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1"
        elif provider == "cloudflare" and not account_id:
            return None, None  # Cloudflare requires account ID

        model = ai_config.get("model") or preset.get("default_model", "")
        if not base_url or not model:
            return None, None

        return OpenAI(api_key=api_key, base_url=base_url), model

    # Fallback to server .env
    api_key = _api_key()
    if not api_key:
        return None, None
    return OpenAI(api_key=api_key, base_url=_base_url()), _model_name()


def _make_client_legacy():
    """Legacy wrapper for backward compat — returns client only (no model)."""
    client, _ = _make_client()
    return client


# ── Synchronous summary (used in maybe_enrich_with_ai) ──────

def build_ai_summary(finding: ExtensionFinding, ai_config: dict[str, str] | None = None) -> str | None:
    client, model = _make_client(ai_config)
    if client is None:
        return None

    signal_lines = "\n".join(
        f"- [{signal.severity}/35] {signal.title}: {signal.detail}"
        for signal in finding.suspicious_signals[:8]
    ) or "- No suspicious signals detected."
    intel_lines = "\n".join(
        f"- [{match.confidence}] {match.label}: {match.detail}"
        for match in finding.intel_matches[:5]
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
Suspicion Score (Code Risk): {finding.anomaly_score}/100
Power Score (Reach): {finding.reach_score}/100
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

    try:
        response = client.chat.completions.create(
            model=model,
            temperature=0.3,
            max_tokens=500,
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity analyst. You speak directly to users, offering insightful, natural, and authoritative security assessments of browser extensions. Do not use generic markdown lists; write fluid, compelling paragraphs."},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content if response.choices else None
    except Exception as e:
        log.warning("AI summary failed for %s: %s", finding.id, e)
        return None


# ── Phase 2 AI (intent / attack / deobfuscate) ──────────────

def _run_in_new_loop(coro):
    """Run a coroutine safely regardless of whether a loop already exists.
    
    FastAPI runs sync endpoints in a thread pool. asyncio.run() works there,
    but sometimes the thread inherits a stale loop reference. We always
    create a fresh loop in a fresh thread to be safe.
    """
    result_holder = {}

    def _thread_target():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result_holder["result"] = loop.run_until_complete(coro)
        except Exception as exc:
            result_holder["exc"] = exc
        finally:
            loop.close()

    t = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = t.submit(_thread_target)
    future.result(timeout=60)  # wait up to 60s
    t.shutdown(wait=True)

    if "exc" in result_holder:
        raise result_holder["exc"]
    return result_holder.get("result")


async def classify_intent(client: Any, model: str, name: str, description: str, bg_snippet: str) -> dict[str, Any] | None:
    if not bg_snippet:
        return None

    prompt = f"""You are a security analyst. Based on the manifest and code snippet, classify this Chrome extension's TRUE purpose into ONE of these categories: [Password Manager, Ad Blocker, Developer Tool, Cryptocurrency Wallet, Social Media Helper, Data Harvester, Utility, Unknown]. Tell me if the code matches the description or if it is deceptive. Respond in strict JSON format: {{"category": "...", "is_deceptive": true/false, "reason": "short reason"}}.

Name: {name}
Description: {description}

Background script snippet:
{bg_snippet}
"""
    try:
        response = await asyncio.to_thread(
            client.chat.completions.create,
            model=model,
            temperature=0.0,
            response_format={"type": "json_object"},
            messages=[{"role": "user", "content": prompt}],
        )
        content = response.choices[0].message.content
        return json.loads(content)
    except Exception as e:
        log.debug("classify_intent failed: %s", e)
        return None


async def simulate_attack(client: Any, model: str, permissions: list[str], active_urls: list[str]) -> str | None:
    if not active_urls or not permissions:
        return None

    prompt = f"""Given this extension's permissions: {permissions} and the user's currently open websites: {active_urls}, write a ONE-SENTENCE, terrifyingly specific narrative of exactly what this extension could steal or modify right now, in plain English. If it is benign or you don't have enough permissions, simply say 'No specific threat detected.' Do not offer advice or bullet points."""
    try:
        response = await asyncio.to_thread(
            client.chat.completions.create,
            model=model,
            temperature=0.7,
            messages=[
                {"role": "system", "content": "You are a red team security analyst. Keep it to one sentence."},
                {"role": "user", "content": prompt}
            ],
        )
        return response.choices[0].message.content
    except Exception as e:
        log.debug("simulate_attack failed: %s", e)
        return None


async def deobfuscate_code(client: Any, model: str, packed_string: str) -> str | None:
    if not packed_string:
        return None

    prompt = f"Decode this JavaScript obfuscated snippet. What is the URL or the specific data exfiltration command hidden inside? Return ONLY the decoded meaningful string. Snippet: {packed_string}"
    try:
        response = await asyncio.to_thread(
            client.chat.completions.create,
            model=model,
            temperature=0.0,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content
    except Exception as e:
        log.debug("deobfuscate_code failed: %s", e)
        return None


def run_phase2_ai(
    name: str,
    description: str,
    bg_snippet: str,
    permissions: list[str],
    active_urls: list[str],
    packed_string: str,
    ai_config: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run phase-2 AI analyses (intent, attack sim, deobfuscation) synchronously.

    Uses a dedicated thread+event-loop so it works from both sync and async
    calling contexts without asyncio.run() conflicts.
    """
    client, model = _make_client(ai_config)
    if client is None:
        return {}

    async def _orchestrate():
        tasks = [
            classify_intent(client, model, name, description, bg_snippet),
            simulate_attack(client, model, permissions, active_urls),
            deobfuscate_code(client, model, packed_string),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {
            "intent": results[0] if not isinstance(results[0], Exception) else None,
            "attack": results[1] if not isinstance(results[1], Exception) else None,
            "deobfuscated": results[2] if not isinstance(results[2], Exception) else None,
        }

    try:
        return _run_in_new_loop(_orchestrate()) or {}
    except Exception as e:
        log.warning("run_phase2_ai failed: %s", e)
        return {}


def maybe_enrich_with_ai(findings: Iterable[ExtensionFinding], enabled: bool, ai_config: dict[str, str] | None = None) -> None:
    """Generate AI summaries for all findings (synchronous, called from scan pipeline).

    Runs summaries in parallel via a thread pool to avoid sequential slowdown
    when scanning many extensions.
    """
    if not enabled:
        return
    client, model = _make_client(ai_config)
    if client is None:
        log.info("AI enrichment skipped: no API key or openai package not installed.")
        return

    findings_list = list(findings)
    if not findings_list:
        return

    log.info("Generating AI summaries for %d extension(s)...", len(findings_list))

    def _summarize(finding: ExtensionFinding) -> None:
        try:
            finding.ai_summary = build_ai_summary(finding, ai_config)
        except Exception as e:
            log.warning("AI summary failed for %s: %s", finding.id, e)

    # Run up to 4 summaries in parallel to keep total time reasonable
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_summarize, f) for f in findings_list]
        for fut in concurrent.futures.as_completed(futures):
            try:
                fut.result(timeout=30)
            except Exception as e:
                log.warning("AI summary thread error: %s", e)

    generated = sum(1 for f in findings_list if f.ai_summary)
    log.info("AI summaries generated: %d / %d", generated, len(findings_list))


async def chat_about_extension(context: dict[str, Any], user_message: str, ai_config: dict[str, str] | None = None) -> str:
    """Interrogate the AI about a specific extension using its scan context."""
    client, model = _make_client(ai_config)
    if client is None:
        return "AI features are disabled. Please configure an AI provider in Settings (gear icon in the header)."

    # Prune full source code from context to save tokens, keep signals and metadata
    pruned_context = {
        "name": context.get("name"),
        "description": context.get("description"),
        "permissions": context.get("permissions"),
        "hostPermissions": context.get("hostPermissions"),
        "reachScore": context.get("reachScore"),
        "anomalyScore": context.get("anomalyScore"),
        "suspiciousSignals": context.get("suspiciousSignals"),
        "category": context.get("category"),
        "verdict": context.get("verdict"),
    }

    system_prompt = f"""You are ManifestGuard AI. You have access to this extension's full scan context:
{json.dumps(pruned_context, indent=2)}

Answer the user's specific questions about security risks in 2 sentences max. Do not hallucinate. If you don't know, say 'I cannot determine that from the static scan.'"""

    try:
        response = await asyncio.to_thread(
            client.chat.completions.create,
            model=model,
            temperature=0.0,
            max_tokens=150,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        )
        return response.choices[0].message.content or "No response generated."
    except Exception as e:
        log.warning("AI chat error: %s", e)
        return "AI analysis is temporarily unavailable. Please try again."


async def test_ai_connection(ai_config: dict[str, str]) -> dict[str, Any]:
    """Test an AI provider connection with a simple prompt."""
    client, model = _make_client(ai_config)
    if client is None:
        return {"success": False, "message": "Could not create AI client. Check your API key and provider settings."}

    try:
        response = await asyncio.to_thread(
            client.chat.completions.create,
            model=model,
            temperature=0.0,
            max_tokens=20,
            messages=[{"role": "user", "content": "Say 'Connection successful' in exactly 2 words."}],
        )
        reply = response.choices[0].message.content or ""
        return {"success": True, "message": f"Connected to {ai_config.get('provider', 'custom')} using model {model}. Response: {reply[:50]}"}
    except Exception as e:
        error_msg = str(e)
        # Sanitize - don't leak API keys in error messages
        if ai_config.get("api_key") and ai_config["api_key"] in error_msg:
            error_msg = error_msg.replace(ai_config["api_key"], "***")
        return {"success": False, "message": f"Connection failed: {error_msg[:200]}"}
