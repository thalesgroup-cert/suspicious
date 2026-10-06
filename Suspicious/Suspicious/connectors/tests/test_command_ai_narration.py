import json
import tempfile
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from case_handler.models import Case, ObservableGroup
from connectors.base import HealthStatus
from connectors.models import ConnectorDelivery, ConnectorState

_HEALTHY = HealthStatus(ok=True, detail="selected provider: ollama (reachable)")


class TestAiNarrationCommandTest(TestCase):
    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r", password="x")
        group = ObservableGroup.objects.create(label="g")
        self.case = Case.objects.create(
            observable_group=group, reporter=reporter, description="",
            results="Dangerous", final_score=9.2, final_confidence=88,
            verdict_explanation={"band": "Dangerous", "confidence": 88, "decisive_rule": "embedded-ioc-escalation"},
        )

    def _write_fixture(self):
        fixture = {
            "verdict": {"band": "Dangerous", "score": 9.2, "confidence": 88, "rule": "embedded-ioc-escalation"},
            "analyzer_reports": [{"analyzer": "VirusTotal_v3", "report_full": {"positives": 50, "total": 70}}],
        }
        tmp_dir = tempfile.mkdtemp()
        path = Path(tmp_dir) / "fixture.json"
        path.write_text(json.dumps(fixture))
        return path

    def test_refuses_when_connector_disabled(self):
        fixture_path = self._write_fixture()
        with self.assertRaises(CommandError):
            call_command("test_ai_narration", fixture=str(fixture_path))
        self.assertEqual(ConnectorDelivery.objects.count(), 0)

    def test_fixture_mode_records_success_delivery(self):
        ConnectorState.objects.update_or_create(name="ai_narration", defaults={"enabled": True})
        fixture_path = self._write_fixture()
        with mock.patch(
            "connectors.contrib.ai_narration.connector.AiNarrationConnector.health_check",
            return_value=_HEALTHY,
        ), mock.patch(
            "connectors.contrib.ai_narration.select.select_provider",
            return_value=("ollama", mock.Mock(return_value="This is Dangerous based on the evidence.")),
        ):
            call_command("test_ai_narration", fixture=str(fixture_path))
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual(delivery.connector, "ai_narration")
        self.assertEqual(delivery.event, "manual_test:ollama")
        self.assertIsNone(delivery.case_id)
        self.assertEqual(delivery.status, ConnectorDelivery.STATUS_SUCCESS)

    def test_case_id_mode_records_success_delivery_with_case_id(self):
        ConnectorState.objects.update_or_create(name="ai_narration", defaults={"enabled": True})
        with mock.patch(
            "connectors.contrib.ai_narration.connector.AiNarrationConnector.health_check",
            return_value=_HEALTHY,
        ), mock.patch(
            "connectors.contrib.ai_narration.select.select_provider",
            return_value=("ollama", mock.Mock(return_value="This is Dangerous based on the evidence.")),
        ):
            call_command("test_ai_narration", case_id=self.case.pk)
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual(delivery.case_id, self.case.pk)
        self.assertEqual(delivery.status, ConnectorDelivery.STATUS_SUCCESS)

    def test_case_without_verdict_explanation_fails_fast(self):
        ConnectorState.objects.update_or_create(name="ai_narration", defaults={"enabled": True})
        unfinalised = Case.objects.create(
            observable_group=self.case.observable_group, reporter=self.case.reporter, description="",
        )
        with self.assertRaises(CommandError):
            call_command("test_ai_narration", case_id=unfinalised.pk)
        self.assertEqual(ConnectorDelivery.objects.count(), 0)

    def test_provider_failure_records_failed_delivery(self):
        ConnectorState.objects.update_or_create(name="ai_narration", defaults={"enabled": True})
        fixture_path = self._write_fixture()

        def _boom(prompt, config):
            raise RuntimeError("provider unreachable")

        with mock.patch(
            "connectors.contrib.ai_narration.connector.AiNarrationConnector.health_check",
            return_value=_HEALTHY,
        ), mock.patch(
            "connectors.contrib.ai_narration.select.select_provider",
            return_value=("ollama", _boom),
        ):
            with self.assertRaises(CommandError):
                call_command("test_ai_narration", fixture=str(fixture_path))
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual(delivery.status, ConnectorDelivery.STATUS_FAILED)
        self.assertIn("provider unreachable", delivery.error)

    def test_unknown_band_case_raises_command_error_no_delivery(self):
        ConnectorState.objects.update_or_create(name="ai_narration", defaults={"enabled": True})
        self.case.results = "Failure"
        self.case.save(update_fields=["results"])
        with self.assertRaises(CommandError):
            call_command("test_ai_narration", case_id=self.case.pk)
        self.assertEqual(ConnectorDelivery.objects.count(), 0)

    def test_unhealthy_provider_raises_before_generation_no_delivery(self):
        ConnectorState.objects.update_or_create(name="ai_narration", defaults={"enabled": True})
        fixture_path = self._write_fixture()
        with mock.patch(
            "connectors.contrib.ai_narration.connector.AiNarrationConnector.health_check",
            return_value=HealthStatus(ok=False, detail="ollama unreachable"),
        ):
            with self.assertRaises(CommandError):
                call_command("test_ai_narration", fixture=str(fixture_path))
        self.assertEqual(ConnectorDelivery.objects.count(), 0)
