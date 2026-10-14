"""Round trip against a real Elasticsearch. Skipped unless ES_SIEM_TEST_URL is set.

ES_SIEM_TEST_URL      base URL of a cluster (security on or off)
ES_SIEM_TEST_API_KEY  the connector's API key (give it only the privileges listed in the
                      spec); defaults to a dummy value, which a cluster with security
                      disabled ignores
ES_SIEM_TEST_ADMIN_KEY  key the test itself uses to read, refresh and drop its index;
                      defaults to ES_SIEM_TEST_API_KEY
ES_SIEM_TEST_VERIFY   "false" to skip TLS verification for a self-signed cluster
"""
import os
import uuid
from unittest import mock, skipUnless

import requests
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail, CaseHasNonFileIocs
from connectors.contrib.elastic_siem import service
from connectors.contrib.elastic_siem.connector import ElasticSiemConnector
from connectors import delivery
from connectors.base import CaseEvent, EVENT_CASE_FINALISED
from connectors.events import build_case_event
from connectors.models import ConnectorDelivery, ConnectorState
from mail_feeder.models import Mail
from url_process.models import URL

ES_URL = os.environ.get("ES_SIEM_TEST_URL")
API_KEY = os.environ.get("ES_SIEM_TEST_API_KEY", "dummy")
ADMIN_KEY = os.environ.get("ES_SIEM_TEST_ADMIN_KEY", API_KEY)
ADMIN_HEADERS = {"Authorization": f"ApiKey {ADMIN_KEY}"}
VERIFY = os.environ.get("ES_SIEM_TEST_VERIFY", "true").lower() != "false"


def _event(case, name):
    return CaseEvent(
        event=name, case_id=case.pk, status=case.status, results=case.results,
        final_score=case.final_score, confidence=case.final_confidence,
        reporter_email="", created_at="2026-10-14T00:00:00+00:00",
    )


@skipUnless(ES_URL, "set ES_SIEM_TEST_URL to run against a real Elasticsearch")
class LiveEsTests(TestCase):
    def setUp(self):
        self.index = f"suspicious-siem-test-{uuid.uuid4().hex[:8]}"
        self.config = {
            "url": ES_URL, "api_key": API_KEY, "index": self.index, "verify_tls": VERIFY,
            "ui_base_url": "https://sus.corp",
        }
        self.session = requests.Session()
        self.addCleanup(self._drop_index)

    def _drop_index(self):
        self.session.delete(f"{ES_URL}/{self.index}", verify=VERIFY,
                            headers=ADMIN_HEADERS)

    def _get(self, case_id):
        self.session.post(f"{ES_URL}/{self.index}/_refresh", verify=VERIFY,
                          headers=ADMIN_HEADERS)
        return self.session.get(f"{ES_URL}/{self.index}/_doc/{case_id}", verify=VERIFY,
                                headers=ADMIN_HEADERS)

    def _count(self):
        self.session.post(f"{ES_URL}/{self.index}/_refresh", verify=VERIFY,
                          headers=ADMIN_HEADERS)
        resp = self.session.get(f"{ES_URL}/{self.index}/_count", verify=VERIFY,
                                headers=ADMIN_HEADERS)
        return resp.json()["count"]

    def _case(self):
        user = User.objects.create_user("alice", "alice@x.io", "pw")
        case = Case.objects.create(
            description="d", reporter=user, results="Dangerous", final_score=9.2,
            final_confidence=88, verdict_explanation={"decisive_rule": "embedded-ioc-escalation"},
        )
        mail = Mail.objects.create(
            subject="Your invoice", reportedBy="r", date=timezone.now(), mail_id="m1",
            mail_from="Bad Guy <bad@evil.test>", to="victim@corp.test",
        )
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save()
        return case

    def test_health(self):
        status = ElasticSiemConnector(self.config).health_check()
        self.assertTrue(status.ok, status.detail)

    def test_wrong_key_fails_health_when_security_is_on(self):
        if requests.get(ES_URL, verify=VERIFY).status_code != 401:
            self.skipTest("cluster has security disabled")
        status = ElasticSiemConnector({**self.config, "api_key": "d3Jvbmc6a2V5"}).health_check()
        self.assertFalse(status.ok)
        self.assertIn("authentication failed", status.detail)

    def test_forward_downgrade_replay_roundtrip(self):
        case = self._case()
        connector = ElasticSiemConnector(self.config)

        connector.on_case_finalised(_event(case, "case_finalised"))
        body = self._get(case.pk).json()["_source"]
        self.assertEqual(body["suspicious"]["verdict"], "Dangerous")
        self.assertEqual(body["email"]["from"]["address"], ["bad@evil.test"])
        self.assertEqual(body["suspicious"]["url"], f"https://sus.corp/investigation?open={case.pk}")

        # Replay is idempotent: one document.
        connector.on_case_finalised(_event(case, "case_finalised"))
        self.assertEqual(self._count(), 1)

        # Analyst downgrade updates the existing document in place.
        case.results = "Safe"
        case.final_score = 1.0
        case.save()
        connector.on_case_modified(_event(case, "case_modified"))
        body = self._get(case.pk).json()["_source"]
        self.assertEqual(body["suspicious"]["verdict"], "Safe")
        self.assertEqual(body["event"]["action"], "case_modified")
        self.assertEqual(body["email"]["subject"], "Your invoice")  # untouched by the partial update
        self.assertEqual(self._count(), 1)

    def test_downgrade_of_never_forwarded_case_creates_nothing(self):
        case = self._case()
        case.results = "Safe"
        case.save()
        # The index exists (a prior case created it) but this case was never forwarded.
        service.SiemClient(self.config).ensure_index()
        ElasticSiemConnector(self.config).on_case_modified(_event(case, "case_modified"))
        self.assertEqual(self._get(case.pk).status_code, 404)
        self.assertEqual(self._count(), 0)

    def test_mappings_are_typed(self):
        case = self._case()
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(
            case=case, url=URL.objects.create(address="http://phish.evil.test/x"))
        case.save()
        ElasticSiemConnector(self.config).on_case_finalised(_event(case, "case_finalised"))
        mapping = self.session.get(
            f"{ES_URL}/{self.index}/_mapping", verify=VERIFY,
            headers=ADMIN_HEADERS).json()[self.index]["mappings"]["properties"]
        self.assertEqual(mapping["related"]["properties"]["ip"]["type"], "ip")
        self.assertEqual(mapping["suspicious"]["properties"]["verdict"]["type"], "keyword")
        self.assertEqual(mapping["@timestamp"]["type"], "date")

    def _deliver(self, case, config, attempt=delivery.MAX_ATTEMPTS):
        """Run one delivery through the real framework path (breaker, ledger)."""
        ConnectorState.objects.update_or_create(name="elastic_siem", defaults={"enabled": True})
        payload = build_case_event(EVENT_CASE_FINALISED, case).to_dict()
        with mock.patch(
            "connectors.registry.ConnectorRegistry.instantiate",
            lambda registry, name: ElasticSiemConnector(config),
        ):
            delivery.deliver_now("elastic_siem", EVENT_CASE_FINALISED, payload, attempt=attempt)

    def test_framework_delivery_records_success_and_indexes(self):
        case = self._case()
        self._deliver(case, self.config)
        row = ConnectorDelivery.objects.get(connector="elastic_siem")
        self.assertEqual(row.status, ConnectorDelivery.STATUS_SUCCESS)
        self.assertEqual(self._get(case.pk).json()["_source"]["suspicious"]["verdict"], "Dangerous")

    def test_framework_delivery_with_wrong_key_records_failure_without_leaking_it(self):
        if requests.get(ES_URL, verify=VERIFY).status_code != 401:
            self.skipTest("cluster has security disabled")
        case = self._case()
        self._deliver(case, {**self.config, "api_key": "d3Jvbmc6a2V5"})
        row = ConnectorDelivery.objects.get(connector="elastic_siem")
        self.assertEqual(row.status, ConnectorDelivery.STATUS_FAILED)
        self.assertIn("authentication failed", row.error)
        self.assertNotIn("d3Jvbmc6a2V5", row.error)
        self.assertEqual(self._get(case.pk).status_code, 404)

    def test_framework_delivery_to_unreachable_cluster_asks_for_a_retry(self):
        case = self._case()
        with self.assertRaises(delivery.RetryableDeliveryError):
            self._deliver(case, {**self.config, "url": "http://127.0.0.1:1", "timeout_seconds": 2}, attempt=1)
        self.assertEqual(ConnectorDelivery.objects.get(connector="elastic_siem").status,
                         ConnectorDelivery.STATUS_FAILED)
