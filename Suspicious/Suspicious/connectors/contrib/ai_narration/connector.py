"""AI narration connector -- architecture test only, see
docs/specs/2026-09-21-ai-narration-connector-design.md's Non-goals. Not
subscribed to any event; drive it via `manage.py test_ai_narration`."""
from __future__ import annotations

import requests

from connectors.base import Connector, ConnectorManifest, ConfigField, HealthStatus

from .select import select_provider


class AiNarrationConnector(Connector):
    manifest = ConnectorManifest(
        name="ai_narration",
        version="0.1.0",
        author="Thales CERT",
        category="AI",
        description=(
            "Generates a plain-language case narration via a locally-run or "
            "externally-configured LLM, validated against the case's "
            "already-computed verdict. Manual/fixture-triggered only in "
            "this phase -- see "
            "docs/specs/2026-09-21-ai-narration-connector-design.md."
        ),
        config_schema=(
            ConfigField("ollama_url", type="url", default="http://localhost:11434"),
            ConfigField("ollama_model", type="str", default="qwen2.5:7b-instruct"),
            ConfigField("openai_api_key", type="secret"),
            ConfigField("openai_model", type="str", default="gpt-4o-mini"),
            ConfigField("anthropic_api_key", type="secret"),
            ConfigField("anthropic_model", type="str", default="claude-haiku-4-5-20251001"),
            ConfigField("gemini_api_key", type="secret"),
            ConfigField("gemini_model", type="str", default="gemini-2.5-flash"),
        ),
        events=(),
        enabled_by_default=False,
    )

    def health_check(self) -> HealthStatus:
        name, _generate = select_provider(self.config)
        if name != "ollama":
            has_key = bool(self.config.get(f"{name}_api_key"))
            return HealthStatus(
                ok=has_key,
                detail=f"selected provider: {name} ({'configured' if has_key else 'no API key'})",
            )
        url = self.config.get("ollama_url") or "http://localhost:11434"
        try:
            requests.get(f"{url}/api/version", timeout=5).raise_for_status()
            return HealthStatus(ok=True, detail=f"selected provider: ollama ({url}, reachable)")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(
                ok=False, detail=f"selected provider: ollama ({url}) unreachable: {exc}"
            )
