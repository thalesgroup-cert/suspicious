"""AI narration connector. Fires automatically on case finalisation,
hardcoded to local Ollama only (see
docs/specs/2026-09-21-ai-narration-event-wiring-design.md) -- the manual
`manage.py test_ai_narration` command remains available separately for
driving any configured provider (including external ones) against a
specific case or fixture. "Ollama only" means no external-provider/API-key
code path exists on this trigger -- it does NOT mean case content stays on
this machine: `ollama_url` is an operator-configurable DB-backed setting and
is the actual trust boundary."""
from __future__ import annotations

import logging

import requests

from connectors.base import CaseEvent, Connector, ConnectorManifest, ConfigField, EVENT_CASE_FINALISED, HealthStatus

from .adapters import analyzer_reports_for_prompt, case_to_verdict_dict
from .providers import ollama
from .select import select_provider

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
            "finalisation (Ollama only); manual/fixture-triggered runs via "
            "`manage.py test_ai_narration` can use any configured provider. "
            "See docs/specs/2026-09-21-ai-narration-event-wiring-design.md."
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
        events=(EVENT_CASE_FINALISED,),
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
        except Exception as exc:  # noqa: BLE001 (health check must not raise)
            return HealthStatus(
                ok=False, detail=f"selected provider: ollama ({url}) unreachable: {exc}"
            )

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
        narration = ollama.generate(prompt, self.config)
        result = validate_narration(narration, verdict)

        logger.info(
            "ai_narration case_finalised: case=%s provider=ollama status=%s "
            "reasons=%s narration=%r",
            event.case_id,
            "PASS" if result.passed else "FAIL",
            result.reasons,
            narration,
        )
