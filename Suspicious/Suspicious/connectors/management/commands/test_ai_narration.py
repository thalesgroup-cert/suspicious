"""Manually drive the ai_narration connector against a real case or a
fixture -- the only way to reach a non-Ollama provider; the connector
also fires automatically via `on_case_finalised` (Ollama-only)."""
import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from case_handler.models import Case
from connectors.contrib.ai_narration.adapters import analyzer_reports_for_prompt, case_to_verdict_dict
from connectors.contrib.ai_narration import select as select_module
from connectors.delivery import get_state
from connectors.models import ConnectorDelivery
from connectors.registry import registry
from score_process.scoring.narration.prompt import build_prompt
from score_process.scoring.narration.verdict_lock import validate_narration


class Command(BaseCommand):
    help = "Manually drive the ai_narration connector against a real case or a fixture."

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--case-id", type=int)
        group.add_argument("--fixture", type=str)

    def handle(self, *args, **options):
        if not get_state("ai_narration").enabled:
            raise CommandError(
                "ai_narration connector is disabled -- set "
                "ConnectorState.enabled=True for name='ai_narration' before running this command."
            )

        if options["case_id"] is not None:
            case_id = options["case_id"]
            try:
                case = Case.objects.get(pk=case_id)
            except Case.DoesNotExist:
                raise CommandError(f"no case with id {case_id}")
            if not case.verdict_explanation:
                raise CommandError(
                    f"case {case_id} has no scoring verdict (verdict_explanation is empty) "
                    f"-- it may be allow-listed or otherwise never scored"
                )
            try:
                verdict = case_to_verdict_dict(case)
            except ValueError as exc:
                raise CommandError(str(exc))
            analyzer_reports = analyzer_reports_for_prompt(case)
        else:
            fixture_path = Path(options["fixture"])
            try:
                fixture = json.loads(fixture_path.read_text())
                verdict = fixture["verdict"]
                analyzer_reports = fixture["analyzer_reports"]
            except (OSError, json.JSONDecodeError, KeyError) as exc:
                raise CommandError(f"invalid fixture {fixture_path}: {exc}")
            case_id = None

        connector = registry.instantiate("ai_narration")
        health = connector.health_check()
        if not health.ok:
            raise CommandError(f"ai_narration provider not usable: {health.detail}")

        prompt = build_prompt(verdict, analyzer_reports)
        provider_name, generate = select_module.select_provider(connector.config)

        started = timezone.now()
        try:
            narration = generate(prompt, connector.config)
        except Exception as exc:  # noqa: BLE001 — record it, don't crash unrecorded
            ConnectorDelivery.objects.create(
                connector="ai_narration", event=f"manual_test:{provider_name}", case_id=case_id,
                status=ConnectorDelivery.STATUS_FAILED, error=str(exc)[:5000],
                duration_ms=int((timezone.now() - started).total_seconds() * 1000),
            )
            raise CommandError(f"provider {provider_name} call failed: {exc}")

        result = validate_narration(narration, verdict)
        ConnectorDelivery.objects.create(
            connector="ai_narration", event=f"manual_test:{provider_name}", case_id=case_id,
            status=ConnectorDelivery.STATUS_SUCCESS,
            duration_ms=int((timezone.now() - started).total_seconds() * 1000),
        )

        status = "PASS" if result.passed else "FAIL"
        self.stdout.write(f"provider: {provider_name}")
        self.stdout.write(f"STATUS: {status}")
        if result.reasons:
            self.stdout.write("REASONS:")
            for reason in result.reasons:
                self.stdout.write(f"  - {reason}")
        self.stdout.write("")
        self.stdout.write("NARRATION:")
        self.stdout.write(narration)
