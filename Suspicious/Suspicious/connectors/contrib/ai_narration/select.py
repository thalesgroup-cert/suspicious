"""Pick which provider a case narration should use. Pure -- no ORM, no
Django models.

Two selectors, deliberately separate:

* ``select_provider`` -- manual path (`manage.py test_ai_narration`) and
  ``health_check``. An explicit ``narration_provider`` wins; otherwise the
  first external provider with an API key wins, else Ollama.
* ``select_auto_provider`` -- the event-driven ``case_finalised`` path.
  Allowlist only, never auto-detected from API-key presence, so a vendor
  provider is unreachable from it by construction."""
from __future__ import annotations

from typing import Callable

from .providers import anthropic, gemini, ollama, openai, openai_compatible

_EXTERNAL_PRIORITY = ("openai", "anthropic", "gemini")

# Providers an automatic case_finalised event may use. Everything else is
# manual-only. See docs/specs/2026-10-14-ai-narration-openai-compatible-design.md.
AUTO_PROVIDERS = ("ollama", "openai_compatible")

PROVIDERS: dict[str, Callable[[str, dict], str]] = {
    "ollama": ollama.generate,
    "openai": openai.generate,
    "anthropic": anthropic.generate,
    "gemini": gemini.generate,
    "openai_compatible": openai_compatible.generate,
}


def select_provider(config: dict) -> tuple[str, Callable[[str, dict], str]]:
    """An explicit ``narration_provider`` naming a known provider wins.
    Otherwise the first external provider (in _EXTERNAL_PRIORITY order) with a
    non-empty API key wins; otherwise Ollama. Ollama's own reachability is
    proven by health_check, not by this selection."""
    explicit = (config.get("narration_provider") or "").strip()
    if explicit in PROVIDERS:
        return explicit, PROVIDERS[explicit]
    for name in _EXTERNAL_PRIORITY:
        if config.get(f"{name}_api_key"):
            return name, PROVIDERS[name]
    return "ollama", PROVIDERS["ollama"]


def select_auto_provider(config: dict) -> tuple[str, Callable[[str, dict], str]]:
    """Provider for the event-driven path. Allowlist only; never auto-detected.
    A disallowed or unknown name raises so the failure lands in the delivery
    ledger instead of silently falling back to a different provider."""
    name = (config.get("narration_provider") or "").strip() or "ollama"
    if name not in AUTO_PROVIDERS:
        raise ValueError(
            f"narration_provider {name!r} is not allowed on the automatic path "
            f"(allowed: {', '.join(AUTO_PROVIDERS)})"
        )
    return name, PROVIDERS[name]
