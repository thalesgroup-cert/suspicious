from unittest import mock

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from case_handler.models import Case, ObservableGroup
from connectors.base import CaseEvent, EVENT_CASE_FINALISED
from connectors.contrib.ai_narration.connector import AiNarrationConnector
from connectors.registry import registry


class AiNarrationManifestTest(SimpleTestCase):
    def test_manifest_valid_and_not_enabled_by_default(self):
        m = AiNarrationConnector.manifest
        m.validate()
        self.assertFalse(m.enabled_by_default)
        self.assertEqual(m.events, (EVENT_CASE_FINALISED,))

    def test_registered_as_a_builtin(self):
        registry.discover()
        self.assertIn("ai_narration", registry.names())


class AiNarrationHealthCheckTest(SimpleTestCase):
    def test_external_provider_configured_reports_ok(self):
        connector = AiNarrationConnector({"openai_api_key": "sk-x"})
        status = connector.health_check()
        self.assertTrue(status.ok)
        self.assertIn("openai", status.detail)

    @mock.patch("connectors.contrib.ai_narration.connector.requests.get")
    def test_ollama_fallback_reachable_reports_ok(self, mock_get):
        mock_get.return_value = mock.Mock()
        mock_get.return_value.raise_for_status = lambda: None
        connector = AiNarrationConnector({})
        status = connector.health_check()
        self.assertTrue(status.ok)
        self.assertIn("ollama", status.detail)

    @mock.patch("connectors.contrib.ai_narration.connector.requests.get")
    def test_ollama_fallback_unreachable_reports_not_ok(self, mock_get):
        mock_get.side_effect = ConnectionError("refused")
        connector = AiNarrationConnector({})
        status = connector.health_check()
        self.assertFalse(status.ok)
        self.assertIn("ollama", status.detail)


def _event(case, status="Done"):
    return CaseEvent(
        event=EVENT_CASE_FINALISED, case_id=case.id, status=status, results=case.results,
        final_score=case.final_score, confidence=case.final_confidence,
        reporter_email="", created_at="2026-09-21T00:00:00+00:00",
    )


class AiNarrationOnCaseFinalisedTest(TestCase):
    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r3", password="x")
        group = ObservableGroup.objects.create(label="g3")
        self.case = Case.objects.create(
            observable_group=group, reporter=reporter, description="",
            results="Dangerous", final_score=9.2, final_confidence=88,
            verdict_explanation={"band": "Dangerous", "confidence": 88, "decisive_rule": "embedded-ioc-escalation"},
        )
        self.connector = AiNarrationConnector({})

    @mock.patch("connectors.contrib.ai_narration.connector.ollama.generate")
    def test_non_done_status_skips_without_calling_provider(self, mock_generate):
        self.connector.on_case_finalised(_event(self.case, status="Ongoing"))
        mock_generate.assert_not_called()

    @mock.patch("connectors.contrib.ai_narration.connector.ollama.generate")
    def test_unknown_band_skips_without_calling_provider(self, mock_generate):
        self.case.results = "Failure"
        self.case.save(update_fields=["results"])
        self.connector.on_case_finalised(_event(self.case, status="Done"))
        mock_generate.assert_not_called()

    @mock.patch("connectors.contrib.ai_narration.connector.ollama.generate")
    def test_happy_path_logs_pass_status_with_narration(self, mock_generate):
        mock_generate.return_value = "This case is Dangerous: an authoritative source confirmed it malicious."
        with self.assertLogs("connectors.contrib.ai_narration", level="INFO") as cm:
            self.connector.on_case_finalised(_event(self.case, status="Done"))
        mock_generate.assert_called_once()
        joined = " ".join(cm.output)
        self.assertIn(f"case={self.case.id}", joined)
        self.assertIn("provider=ollama", joined)
        self.assertIn("status=PASS", joined)

    @mock.patch("connectors.contrib.ai_narration.connector.ollama.generate")
    def test_provider_failure_propagates(self, mock_generate):
        mock_generate.side_effect = RuntimeError("ollama unreachable")
        with self.assertRaises(RuntimeError):
            self.connector.on_case_finalised(_event(self.case, status="Done"))
