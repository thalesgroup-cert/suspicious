import functools
from unittest import mock

import requests

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from case_handler.models import Case, ObservableGroup
from connectors.base import CaseEvent, EVENT_CASE_FINALISED
from connectors.contrib.ai_narration.connector import AiNarrationConnector
from connectors.contrib.ai_narration.select import PROVIDERS
from connectors.registry import registry


def provider_mock(name):
    """Swap PROVIDERS[name] for a mock, passed to the test as an extra arg."""
    def decorator(test):
        @functools.wraps(test)
        def wrapper(self, *args, **kwargs):
            replacement = mock.Mock()
            with mock.patch.dict(PROVIDERS, {name: replacement}):
                return test(self, replacement, *args, **kwargs)
        return wrapper
    return decorator


class AiNarrationManifestTest(SimpleTestCase):
    def test_manifest_valid_and_not_enabled_by_default(self):
        m = AiNarrationConnector.manifest
        m.validate()
        self.assertFalse(m.enabled_by_default)
        self.assertEqual(m.events, (EVENT_CASE_FINALISED,))

    def test_registered_as_a_builtin(self):
        registry.discover()
        self.assertIn("ai_narration", registry.names())

    def test_openai_compatible_fields_declared(self):
        fields = {f.key: f for f in AiNarrationConnector.manifest.config_schema}
        for key in (
            "narration_provider", "openai_compatible_base_url",
            "openai_compatible_api_key", "openai_compatible_model",
        ):
            self.assertIn(key, fields)
        self.assertEqual(fields["openai_compatible_api_key"].type, "secret")
        self.assertIsNone(fields["openai_compatible_base_url"].default)
        self.assertIsNone(fields["openai_compatible_model"].default)
        self.assertFalse(fields["openai_compatible_model"].required)
        self.assertEqual(fields["narration_provider"].default, "ollama")


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


def _response(status_code):
    response = mock.Mock(status_code=status_code)
    response.raise_for_status.side_effect = (
        requests.HTTPError(f"{status_code}") if status_code >= 400 else None
    )
    return response


class AiNarrationOpenAICompatibleHealthCheckTest(SimpleTestCase):
    _CONFIG = {
        "narration_provider": "openai_compatible",
        "openai_compatible_base_url": "https://gw.internal/v1/",
    }

    def _check(self, config=None, **get_kwargs):
        with mock.patch("connectors.contrib.ai_narration.connector.requests.get", **get_kwargs) as mock_get:
            status = AiNarrationConnector(config or self._CONFIG).health_check()
        return status, mock_get

    def test_2xx_reports_ok_and_probes_models_route(self):
        status, mock_get = self._check(return_value=_response(200))
        self.assertTrue(status.ok)
        self.assertIn("reachable", status.detail)
        self.assertEqual(mock_get.call_args[0][0], "https://gw.internal/v1/models")
        self.assertEqual(mock_get.call_args[1]["timeout"], 5)

    def test_404_reports_ok_with_no_models_route(self):
        status, _ = self._check(return_value=_response(404))
        self.assertTrue(status.ok)
        self.assertIn("no /models route", status.detail)

    def test_401_and_403_report_authentication_failed(self):
        for code in (401, 403):
            status, _ = self._check(return_value=_response(code))
            self.assertFalse(status.ok)
            self.assertIn("authentication failed", status.detail)

    def test_other_4xx_and_5xx_report_not_ok_with_detail(self):
        for code in (400, 429, 500, 503):
            status, _ = self._check(return_value=_response(code))
            self.assertFalse(status.ok)
            self.assertIn(str(code), status.detail)

    def test_timeout_and_connection_error_report_not_ok_without_raising(self):
        for exc in (requests.Timeout("slow"), requests.ConnectionError("refused")):
            status, _ = self._check(side_effect=exc)
            self.assertFalse(status.ok)
            self.assertIn("openai_compatible", status.detail)

    def test_unset_base_url_reports_not_ok_without_calling_endpoint(self):
        for config in ({"narration_provider": "openai_compatible"},
                       {"narration_provider": "openai_compatible", "openai_compatible_base_url": " "}):
            status, mock_get = self._check(config)
            self.assertFalse(status.ok)
            self.assertIn("openai_compatible_base_url not set", status.detail)
            mock_get.assert_not_called()

    def test_api_key_sent_as_bearer_when_set(self):
        _, mock_get = self._check({**self._CONFIG, "openai_compatible_api_key": "k-test"},
                                  return_value=_response(200))
        self.assertEqual(mock_get.call_args[1]["headers"]["Authorization"], "Bearer k-test")

    def test_no_authorization_header_without_key(self):
        _, mock_get = self._check(return_value=_response(200))
        self.assertNotIn("Authorization", mock_get.call_args[1]["headers"])


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

    @provider_mock("ollama")
    def test_non_done_status_skips_without_calling_provider(self, mock_generate):
        self.connector.on_case_finalised(_event(self.case, status="Ongoing"))
        mock_generate.assert_not_called()

    @provider_mock("ollama")
    def test_unknown_band_skips_without_calling_provider(self, mock_generate):
        self.case.results = "Failure"
        self.case.save(update_fields=["results"])
        self.connector.on_case_finalised(_event(self.case, status="Done"))
        mock_generate.assert_not_called()

    @provider_mock("ollama")
    def test_happy_path_logs_pass_status_with_narration(self, mock_generate):
        mock_generate.return_value = "This case is Dangerous: an authoritative source confirmed it malicious."
        with self.assertLogs("connectors.contrib.ai_narration", level="INFO") as cm:
            self.connector.on_case_finalised(_event(self.case, status="Done"))
        mock_generate.assert_called_once()
        joined = " ".join(cm.output)
        self.assertIn(f"case={self.case.id}", joined)
        self.assertIn("provider=ollama", joined)
        self.assertIn("status=PASS", joined)

    @provider_mock("ollama")
    def test_fail_status_logs_with_reasons(self, mock_generate):
        mock_generate.return_value = "This item is completely safe, nothing to worry about."
        with self.assertLogs("connectors.contrib.ai_narration", level="INFO") as cm:
            self.connector.on_case_finalised(_event(self.case, status="Done"))
        mock_generate.assert_called_once()
        joined = " ".join(cm.output)
        self.assertIn(f"case={self.case.id}", joined)
        self.assertIn("provider=ollama", joined)
        self.assertIn("status=FAIL", joined)
        self.assertNotIn("reasons=[]", joined)

    @provider_mock("ollama")
    def test_provider_failure_propagates(self, mock_generate):
        mock_generate.side_effect = RuntimeError("ollama unreachable")
        with self.assertRaises(RuntimeError):
            self.connector.on_case_finalised(_event(self.case, status="Done"))


class AiNarrationProviderDispatchTest(TestCase):
    """The automatic path dispatches through select_auto_provider's allowlist."""

    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r4", password="x")
        group = ObservableGroup.objects.create(label="g4")
        self.case = Case.objects.create(
            observable_group=group, reporter=reporter, description="",
            results="Dangerous", final_score=9.2, final_confidence=88,
            verdict_explanation={"band": "Dangerous", "confidence": 88, "decisive_rule": "embedded-ioc-escalation"},
        )

    def test_openai_compatible_is_called_and_ollama_is_not(self):
        connector = AiNarrationConnector({"narration_provider": "openai_compatible"})
        compat, ollama_mock = mock.Mock(), mock.Mock()
        compat.return_value = "This case is Dangerous: an authoritative source confirmed it malicious."
        with mock.patch.dict(PROVIDERS, {"openai_compatible": compat, "ollama": ollama_mock}):
            with self.assertLogs("connectors.contrib.ai_narration", level="INFO") as cm:
                connector.on_case_finalised(_event(self.case))
        compat.assert_called_once()
        ollama_mock.assert_not_called()
        self.assertEqual(compat.call_args[0][1], connector.config)
        self.assertIn("provider=openai_compatible", " ".join(cm.output))

    def test_disallowed_provider_raises_and_calls_no_provider(self):
        for value in ("openai", "anthropic", "gemini", "typo"):
            connector = AiNarrationConnector({"narration_provider": value, f"{value}_api_key": "k"})
            replacements = {name: mock.Mock() for name in PROVIDERS}
            with mock.patch.dict(PROVIDERS, replacements):
                with self.assertRaises(ValueError):
                    connector.on_case_finalised(_event(self.case))
            for replacement in replacements.values():
                replacement.assert_not_called()

    def test_vendor_key_presence_does_not_divert_the_automatic_path(self):
        connector = AiNarrationConnector({"openai_api_key": "sk-x"})
        ollama_mock, openai_mock = mock.Mock(), mock.Mock()
        ollama_mock.return_value = "This case is Dangerous."
        with mock.patch.dict(PROVIDERS, {"ollama": ollama_mock, "openai": openai_mock}):
            connector.on_case_finalised(_event(self.case))
        ollama_mock.assert_called_once()
        openai_mock.assert_not_called()
