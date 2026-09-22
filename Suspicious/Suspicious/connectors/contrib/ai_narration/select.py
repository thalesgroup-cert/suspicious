"""Auto-detect which provider a case narration should use. Pure -- no ORM,
no Django models."""
from __future__ import annotations

from typing import Callable

from .providers import anthropic, gemini, ollama, openai

_EXTERNAL_PRIORITY = ("openai", "anthropic", "gemini")

PROVIDERS: dict[str, Callable[[str, dict], str]] = {
    "ollama": ollama.generate,
    "openai": openai.generate,
    "anthropic": anthropic.generate,
    "gemini": gemini.generate,
}


def select_provider(config: dict) -> tuple[str, Callable[[str, dict], str]]:
    """The first external provider (in _EXTERNAL_PRIORITY order) with a
    non-empty API key wins; otherwise Ollama. Ollama's own reachability is
    proven by health_check, not by this selection."""
    for name in _EXTERNAL_PRIORITY:
        if config.get(f"{name}_api_key"):
            return name, PROVIDERS[name]
    return "ollama", PROVIDERS["ollama"]
