"""AI narration connector. Fires automatically on case finalisation, limited
to an explicit allowlist (`select.AUTO_PROVIDERS`): local Ollama (the
default) or an operator-declared OpenAI-compatible endpoint (see
docs/specs/2026-09-21-ai-narration-event-wiring-design.md and
docs/specs/2026-10-14-ai-narration-openai-compatible-design.md) -- the manual
`manage.py test_ai_narration` command remains available separately for
driving any configured provider (including the OpenAI/Anthropic/Gemini
vendors) against a specific case or fixture. The allowlist means no
vendor/API-key-detection code path exists on this trigger -- it does NOT
mean case content stays on this machine: `ollama_url` and
`openai_compatible_base_url` are operator-configurable DB-backed settings
and are the actual trust boundary."""
from __future__ import annotations

import logging

import requests

from connectors.base import CaseEvent, Connector, ConnectorManifest, ConfigField, EVENT_CASE_FINALISED, HealthStatus

from .adapters import analyzer_reports_for_prompt, case_to_verdict_dict
from .select import select_auto_provider, select_provider

logger = logging.getLogger("connectors.contrib.ai_narration")


class AiNarrationConnector(Connector):
    manifest = ConnectorManifest(
        name="ai_narration",
        version="0.1.0",
        author="Thales CERT",
        category="AI",
        description=(
            "Generates a plain-language case narration via a locally-run or "
            "externally-configured LLM, validated against the case's "
            "already-computed verdict. Fires automatically on case "
            "finalisation via Ollama (default) or an operator-declared "
            "OpenAI-compatible endpoint; manual/fixture-triggered runs via "
            "`manage.py test_ai_narration` can use any configured provider. "
            "See docs/specs/2026-10-14-ai-narration-openai-compatible-design.md."
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
            ConfigField(
                "narration_provider", type="str", default="ollama",
                help="Provider used when narration fires automatically: "
                     "'ollama' or 'openai_compatible'.",
            ),
            ConfigField(
                "openai_compatible_base_url", type="url",
                help="Base URL including version prefix, e.g. https://gw.internal/v1. "
                     "No default: must be set deliberately.",
            ),
            ConfigField(
                "openai_compatible_api_key", type="secret",
                help="Optional. Omit for servers that do not check a key.",
            ),
            ConfigField("openai_compatible_model", type="str", required=False),
        ),
        events=(EVENT_CASE_FINALISED,),
        enabled_by_default=False,
    )

    def health_check(self) -> HealthStatus:
        name, _generate = select_provider(self.config)
        if name == "openai_compatible":
            return self._check_openai_compatible()
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
        except Exception as exc:  # noqa: BLE001 (health check must not raise)
            return HealthStatus(
                ok=False, detail=f"selected provider: ollama ({url}) unreachable: {exc}"
            )

    def _check_openai_compatible(self) -> HealthStatus:
        base = (self.config.get("openai_compatible_base_url") or "").strip().rstrip("/")
        if not base:
            return HealthStatus(
                ok=False,
                detail="selected provider: openai_compatible (openai_compatible_base_url not set)",
            )
        headers = {}
        if self.config.get("openai_compatible_api_key"):
            headers["Authorization"] = f"Bearer {self.config['openai_compatible_api_key']}"
        label = f"selected provider: openai_compatible ({base}"
        try:
            response = requests.get(f"{base}/models", headers=headers, timeout=5)
        except Exception as exc:  # noqa: BLE001 (health check must not raise)
            return HealthStatus(ok=False, detail=f"{label}) unreachable: {exc}")
        code = response.status_code
        if 200 <= code < 300:
            return HealthStatus(ok=True, detail=f"{label}, reachable)")
        if code == 404:
            # Gateways often omit /models; the host answered, so it is up.
            return HealthStatus(ok=True, detail=f"{label}, reachable (no /models route))")
        if code in (401, 403):
            return HealthStatus(ok=False, detail=f"{label}) authentication failed (HTTP {code})")
        return HealthStatus(ok=False, detail=f"{label}) returned HTTP {code}")

    def on_case_finalised(self, event: CaseEvent) -> None:
        if event.status != "Done":
            return

        from case_handler.models import Case
        from score_process.scoring.narration.prompt import build_prompt
        from score_process.scoring.narration.verdict_lock import validate_narration

        case = Case.objects.get(pk=event.case_id)
        try:
            verdict = case_to_verdict_dict(case)
        except ValueError:
            logger.info(
                "ai_narration: case %s has a band the lock doesn't model, skipping",
                event.case_id,
            )
            return

        analyzer_reports = analyzer_reports_for_prompt(case)
        prompt = build_prompt(verdict, analyzer_reports)
        provider_name, generate = select_auto_provider(self.config)
        narration = generate(prompt, self.config)
        result = validate_narration(narration, verdict)

        logger.info(
            "ai_narration case_finalised: case=%s provider=%s status=%s "
            "reasons=%s narration=%r",
            event.case_id,
            provider_name,
            "PASS" if result.passed else "FAIL",
            result.reasons,
            narration,
        )
