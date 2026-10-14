from unittest import mock

import requests
from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase

from case_handler.models import Case
from connectors.base import CaseEvent, EVENT_CASE_FINALISED, EVENT_CASE_MODIFIED
from connectors.contrib.elastic_siem import service
from connectors.contrib.elastic_siem.connector import ElasticSiemConnector
from connectors.contrib.elastic_siem.tests.test_service import fake_response
from connectors.registry import registry

CONFIG = {"url": "https://siem.corp:9200", "api_key": "KEY123", "index": "idx"}


class ManifestTests(SimpleTestCase):
    def test_manifest(self):
        m = ElasticSiemConnector.manifest
        m.validate()
        self.assertEqual(m.name, "elastic_siem")
        self.assertFalse(m.enabled_by_default)
        self.assertEqual(set(m.events), {EVENT_CASE_FINALISED, EVENT_CASE_MODIFIED})

    def test_fields(self):
        fields = {f.key: f for f in ElasticSiemConnector.manifest.config_schema}
        self.assertEqual(set(fields), {
            "url", "api_key", "index", "min_verdict", "verify_tls", "timeout_seconds",
            "create_index", "ui_base_url",
        })
        self.assertEqual(fields["api_key"].type, "secret")
        self.assertTrue(fields["url"].required)
        self.assertTrue(fields["api_key"].required)
        self.assertEqual(fields["min_verdict"].default, "Suspicious")
        self.assertIs(fields["verify_tls"].default, True)
        self.assertIs(fields["create_index"].default, True)
        self.assertEqual(fields["index"].default, "suspicious-cases-siem")
        self.assertFalse(fields["ui_base_url"].required)

    def test_registered_as_a_builtin(self):
        registry.discover()
        self.assertIn("elastic_siem", registry.names())


def _event(case, name=EVENT_CASE_FINALISED):
    return CaseEvent(
        event=name, case_id=case.pk, status=case.status, results=case.results,
        final_score=case.final_score, confidence=case.final_confidence,
        reporter_email="", created_at="2026-10-14T00:00:00+00:00",
    )


class HookTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", "alice@x.io", "pw")

    def _case(self, results):
        return Case.objects.create(description="d", reporter=self.user, results=results,
                                   final_score=5.0, final_confidence=60)

    def _run(self, case, hook, config=None, event_name=EVENT_CASE_FINALISED):
        client = mock.Mock()
        client.update_case.return_value = True
        with mock.patch.object(service, "SiemClient", return_value=client) as cls:
            connector = ElasticSiemConnector({**CONFIG, **(config or {})})
            getattr(connector, hook)(_event(case, event_name))
        return client, cls

    def test_finalised_at_threshold_upserts(self):
        case = self._case("Dangerous")
        client, _ = self._run(case, "on_case_finalised")
        client.ensure_index.assert_called_once_with()
        client.put_case.assert_called_once()
        case_id, doc = client.put_case.call_args[0]
        self.assertEqual(case_id, case.pk)
        self.assertEqual(doc["suspicious"]["verdict"], "Dangerous")
        self.assertEqual(doc["event"]["action"], "case_finalised")
        client.update_case.assert_not_called()

    def test_finalised_below_threshold_sends_nothing(self):
        for results in ("Safe", "Inconclusive", "AllowListed", "Unchallenged", "Failure"):
            client, _ = self._run(self._case(results), "on_case_finalised")
            client.ensure_index.assert_not_called()
            client.put_case.assert_not_called()
            client.update_case.assert_not_called()

    def test_modified_at_threshold_upserts(self):
        case = self._case("Suspicious")
        client, _ = self._run(case, "on_case_modified", event_name=EVENT_CASE_MODIFIED)
        client.put_case.assert_called_once()
        self.assertEqual(client.put_case.call_args[0][1]["event"]["action"], "case_modified")
        client.update_case.assert_not_called()

    def test_modified_below_threshold_updates_existing_document_only(self):
        case = self._case("Safe")
        client, _ = self._run(case, "on_case_modified", event_name=EVENT_CASE_MODIFIED)
        client.put_case.assert_not_called()
        client.ensure_index.assert_not_called()  # a downgrade never creates the index
        client.update_case.assert_called_once()
        case_id, partial = client.update_case.call_args[0]
        self.assertEqual(case_id, case.pk)
        self.assertEqual(partial["suspicious"]["verdict"], "Safe")

    def test_modified_unranked_does_nothing(self):
        for results in ("Unchallenged", "Failure"):
            client, _ = self._run(self._case(results), "on_case_modified", event_name=EVENT_CASE_MODIFIED)
            client.put_case.assert_not_called()
            client.update_case.assert_not_called()

    def test_min_verdict_is_honoured(self):
        client, _ = self._run(self._case("Safe"), "on_case_finalised", {"min_verdict": "Safe"})
        client.put_case.assert_called_once()
        client, _ = self._run(self._case("Suspicious"), "on_case_finalised", {"min_verdict": "Dangerous"})
        client.put_case.assert_not_called()

    def test_unknown_min_verdict_raises_and_sends_nothing(self):
        client = mock.Mock()
        with mock.patch.object(service, "SiemClient", return_value=client):
            connector = ElasticSiemConnector({**CONFIG, "min_verdict": "Banana"})
            with self.assertRaises(ValueError):
                connector.on_case_finalised(_event(self._case("Dangerous")))
        client.put_case.assert_not_called()

    def test_ui_base_url_reaches_the_document(self):
        case = self._case("Dangerous")
        client, _ = self._run(case, "on_case_finalised", {"ui_base_url": "https://sus.corp"})
        self.assertEqual(client.put_case.call_args[0][1]["suspicious"]["url"],
                         f"https://sus.corp/investigation?open={case.pk}")

    def test_missing_case_is_ignored(self):
        case = self._case("Dangerous")
        event = _event(case)
        case.delete()
        client = mock.Mock()
        with mock.patch.object(service, "SiemClient", return_value=client):
            ElasticSiemConnector(CONFIG).on_case_finalised(event)
        client.put_case.assert_not_called()

    def test_client_errors_propagate_so_the_framework_retries(self):
        case = self._case("Dangerous")
        for exc in (service.SiemError("HTTP 500"), requests.Timeout("slow")):
            client = mock.Mock()
            client.put_case.side_effect = exc
            with mock.patch.object(service, "SiemClient", return_value=client):
                with self.assertRaises(type(exc)):
                    ElasticSiemConnector(CONFIG).on_case_finalised(_event(case))

    def test_unconfigured_connector_raises(self):
        with self.assertRaises(ValueError):
            ElasticSiemConnector({}).on_case_finalised(_event(self._case("Dangerous")))


class HealthCheckTests(SimpleTestCase):
    def _check(self, config=None, **request_kwargs):
        session = mock.Mock()
        session.request.configure_mock(**request_kwargs)
        with mock.patch.object(service, "make_session", return_value=session):
            status = ElasticSiemConnector(CONFIG if config is None else config).health_check()
        return status, session

    def test_2xx_reports_ok_with_version(self):
        status, session = self._check(return_value=fake_response(200, {"version": {"number": "8.19.7"}}))
        self.assertTrue(status.ok)
        self.assertIn("reachable", status.detail)
        self.assertIn("8.19.7", status.detail)
        args, kwargs = session.request.call_args
        self.assertEqual(args, ("GET", "https://siem.corp:9200/"))
        self.assertEqual(kwargs["timeout"], 5)
        self.assertEqual(kwargs["headers"]["Authorization"], "ApiKey KEY123")

    def test_2xx_without_version_is_still_ok(self):
        status, _ = self._check(return_value=fake_response(200, text="not json"))
        self.assertTrue(status.ok)

    def test_401_and_403_report_authentication_failed(self):
        for code in (401, 403):
            status, _ = self._check(return_value=fake_response(code, text="KEY123"))
            self.assertFalse(status.ok)
            self.assertIn("authentication failed", status.detail)
            self.assertNotIn("KEY123", status.detail)

    def test_other_statuses_report_not_ok_with_detail(self):
        for code in (400, 404, 500, 503):
            status, _ = self._check(return_value=fake_response(code))
            self.assertFalse(status.ok)
            self.assertIn(str(code), status.detail)

    def test_timeout_and_connection_error_report_not_ok_without_raising(self):
        for exc in (requests.Timeout("slow"), requests.ConnectionError("refused")):
            status, _ = self._check(side_effect=exc)
            self.assertFalse(status.ok)

    def test_unset_url_or_key_reports_not_ok_without_calling(self):
        for config in ({}, {"url": "https://x"}, {"api_key": "k"}):
            status, session = self._check(config)
            self.assertFalse(status.ok)
            self.assertIn("url/api_key not configured", status.detail)
            session.request.assert_not_called()

    def test_bad_min_verdict_reports_not_ok_naming_the_field(self):
        status, session = self._check({**CONFIG, "min_verdict": "Banana"})
        self.assertFalse(status.ok)
        self.assertIn("min_verdict", status.detail)
        session.request.assert_not_called()
