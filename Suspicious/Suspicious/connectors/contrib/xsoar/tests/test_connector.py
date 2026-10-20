from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase

from case_handler.models import Case
from connectors.base import EVENT_CASE_FINALISED, CaseEvent, HealthStatus
from connectors.contrib.xsoar import service
from connectors.contrib.xsoar.connector import NAME, XsoarConnector
from connectors.models import ConnectorLink
from connectors.registry import registry

CONFIG = {"url": "https://xsoar.corp", "api_key": "KEY123"}


class ManifestTests(SimpleTestCase):
    def test_manifest(self):
        m = XsoarConnector.manifest
        m.validate()
        self.assertEqual(m.name, "xsoar")
        self.assertEqual(m.category, "SOAR")
        self.assertFalse(m.enabled_by_default)
        self.assertEqual(m.events, (EVENT_CASE_FINALISED,))

    def test_fields(self):
        fields = {f.key: f for f in XsoarConnector.manifest.config_schema}
        self.assertEqual(set(fields), {
            "url", "api_key", "api_key_id", "incident_type", "min_verdict", "create_investigation",
            "skip_ref_prefix", "verify_tls", "timeout_seconds", "ui_base_url",
        })
        self.assertEqual(fields["api_key"].type, "secret")
        self.assertTrue(fields["url"].required)
        self.assertTrue(fields["api_key"].required)
        self.assertEqual(fields["min_verdict"].default, "Suspicious")
        self.assertEqual(fields["skip_ref_prefix"].default, "xsoar:")
        self.assertIs(fields["create_investigation"].default, True)
        self.assertIs(fields["verify_tls"].default, True)

    def test_registered_as_a_builtin(self):
        registry.discover()
        self.assertIn("xsoar", registry.names())


def _event(case):
    return CaseEvent(
        event=EVENT_CASE_FINALISED, case_id=case.pk, status=case.status, results=case.results,
        final_score=case.final_score, confidence=case.final_confidence,
        reporter_email="", created_at="2026-10-20T00:00:00+00:00",
    )


class HookTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", "alice@x.io", "pw")

    def _case(self, results="Dangerous", **extra):
        return Case.objects.create(
            description="d", reporter=self.user, results=results,
            final_score=92.0, final_confidence=0.8, category_ai="Phishing", **extra,
        )

    def _run(self, case, config=None, client=None):
        client = client or mock.Mock()
        if not isinstance(client.create_incident.return_value, str):
            client.create_incident.return_value = "1042"
        with mock.patch.object(service, "XsoarClient", return_value=client):
            XsoarConnector({**CONFIG, **(config or {})}).on_case_finalised(_event(case))
        return client

    def test_dangerous_case_creates_one_incident_and_records_it(self):
        case = self._case()
        client = self._run(case, {"incident_type": "Phishing", "ui_base_url": "https://sus.corp"})
        client.create_incident.assert_called_once()
        body = client.create_incident.call_args[0][0]
        self.assertEqual(body["name"], f"Suspicious case #{case.pk}: Dangerous")
        self.assertEqual(body["type"], "Phishing")
        self.assertEqual(body["severity"], 4)
        self.assertIn(f"investigation?open={case.pk}", body["details"])
        link = ConnectorLink.objects.get(connector=NAME, case_id=case.pk)
        self.assertEqual(link.remote_id, "1042")

    def test_a_replayed_finalised_event_does_not_open_a_second_incident(self):
        case = self._case()
        self._run(case)
        client = self._run(case)
        client.create_incident.assert_not_called()
        self.assertEqual(ConnectorLink.objects.filter(connector=NAME, case_id=case.pk).count(), 1)

    def test_below_threshold_pushes_nothing(self):
        for results in ("Safe", "Inconclusive", "AllowListed", "Unchallenged", "Failure"):
            client = self._run(self._case(results))
            client.create_incident.assert_not_called()
        self.assertFalse(ConnectorLink.objects.exists())

    def test_threshold_is_configurable(self):
        self.assertEqual(self._run(self._case("Suspicious"), {"min_verdict": "Dangerous"}).create_incident.call_count, 0)
        self.assertEqual(self._run(self._case("Inconclusive"), {"min_verdict": "Inconclusive"}).create_incident.call_count, 1)

    def test_invalid_threshold_is_an_error_before_any_io(self):
        client = mock.Mock()
        with self.assertRaisesRegex(ValueError, "min_verdict"):
            self._run(self._case(), {"min_verdict": "Critical"}, client=client)
        client.create_incident.assert_not_called()

    def test_cases_submitted_by_xsoar_are_not_pushed_back(self):
        client = self._run(self._case(external_ref="xsoar:1042:url:ab12"))
        client.create_incident.assert_not_called()
        self.assertFalse(ConnectorLink.objects.exists())

    def test_other_references_are_pushed_and_labelled(self):
        client = self._run(self._case(external_ref="jira:42"))
        body = client.create_incident.call_args[0][0]
        self.assertIn({"type": "External reference", "value": "jira:42"}, body["labels"])

    def test_skip_prefix_is_configurable_and_can_be_turned_off(self):
        self.assertEqual(
            self._run(self._case(external_ref="soar-9"), {"skip_ref_prefix": "soar-"}).create_incident.call_count, 0,
        )
        self.assertEqual(
            self._run(self._case(external_ref="xsoar:1"), {"skip_ref_prefix": ""}).create_incident.call_count, 1,
        )

    def test_failed_push_records_nothing_and_the_retry_succeeds(self):
        case = self._case()
        broken = mock.Mock()
        broken.create_incident.side_effect = service.XsoarError("create incident: HTTP 500")
        with self.assertRaises(service.XsoarError):
            self._run(case, client=broken)
        self.assertFalse(ConnectorLink.objects.filter(connector=NAME, case_id=case.pk).exists())

        client = self._run(case)
        client.create_incident.assert_called_once()
        self.assertEqual(ConnectorLink.objects.get(connector=NAME, case_id=case.pk).remote_id, "1042")

    def test_answer_without_an_id_still_counts_as_pushed(self):
        case = self._case()
        client = mock.Mock()
        client.create_incident.return_value = ""
        self._run(case, client=client)
        self.assertEqual(ConnectorLink.objects.get(connector=NAME, case_id=case.pk).remote_id, "created")
        self._run(case).create_incident.assert_not_called()

    def test_options_reach_the_incident(self):
        client = self._run(self._case(), {"create_investigation": False})
        self.assertFalse(client.create_incident.call_args[0][0]["createInvestigation"])

    def test_unknown_case_is_ignored(self):
        case = self._case()
        event = _event(case)
        case.delete()
        client = mock.Mock()
        with mock.patch.object(service, "XsoarClient", return_value=client):
            XsoarConnector(CONFIG).on_case_finalised(event)
        client.create_incident.assert_not_called()


class HealthTests(SimpleTestCase):
    def test_passes_the_client_answer_through(self):
        client = mock.Mock()
        client.health.return_value = HealthStatus(ok=True, detail="reachable, key accepted")
        with mock.patch.object(service, "XsoarClient", return_value=client):
            self.assertTrue(XsoarConnector(CONFIG).health_check().ok)

    def test_configuration_errors_are_reported_not_raised(self):
        status = XsoarConnector({"url": "", "api_key": ""}).health_check()
        self.assertFalse(status.ok)
        self.assertIn("not configured", status.detail)
        status = XsoarConnector({**CONFIG, "min_verdict": "nope"}).health_check()
        self.assertFalse(status.ok)
        self.assertIn("min_verdict", status.detail)


class FrameworkTests(TestCase):
    """Through the real delivery pipeline: config lookup, ledger row, retry."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("bob", "bob@x.io", "pw")

    def setUp(self):
        registry.discover()
        self.case = Case.objects.create(
            description="d", reporter=self.user, results="Dangerous", final_score=92.0, final_confidence=0.8,
        )
        self.payload = _event(self.case).to_dict()

    def _deliver(self, section, client=None):
        from connectors.delivery import deliver_now

        client = client or mock.Mock(create_incident=mock.Mock(return_value="77"))
        with mock.patch("settings.config.get_section", return_value=section), \
                mock.patch.object(service, "XsoarClient", return_value=client):
            deliver_now(NAME, EVENT_CASE_FINALISED, self.payload)
        return client

    def _deliver_unconfigured(self, section):
        """Real XsoarClient, so its config validation runs."""
        from connectors.delivery import deliver_now

        with mock.patch("settings.config.get_section", return_value=section):
            deliver_now(NAME, EVENT_CASE_FINALISED, self.payload)

    def test_delivery_records_success_and_the_link(self):
        from connectors.models import ConnectorDelivery

        client = self._deliver(CONFIG)
        client.create_incident.assert_called_once()
        row = ConnectorDelivery.objects.get(connector=NAME, case_id=self.case.pk)
        self.assertEqual(row.status, ConnectorDelivery.STATUS_SUCCESS)
        self.assertEqual(ConnectorLink.objects.get(connector=NAME, case_id=self.case.pk).remote_id, "77")

    def test_unconfigured_connector_is_recorded_as_failed_and_retried(self):
        from connectors.delivery import RetryableDeliveryError
        from connectors.models import ConnectorDelivery

        with self.assertRaises(RetryableDeliveryError):
            self._deliver_unconfigured({"url": "", "api_key": ""})
        row = ConnectorDelivery.objects.get(connector=NAME, case_id=self.case.pk)
        self.assertEqual(row.status, ConnectorDelivery.STATUS_FAILED)
        self.assertIn("not configured", row.error)
        self.assertFalse(ConnectorLink.objects.exists())
