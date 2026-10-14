"""Round trip against a real Elasticsearch. Skipped unless ES_SIEM_TEST_URL is set.

ES_SIEM_TEST_URL      base URL of a cluster (security on or off)
ES_SIEM_TEST_API_KEY  API key for it; defaults to a dummy value, which a
                      cluster with security disabled ignores
ES_SIEM_TEST_VERIFY   "false" to skip TLS verification for a self-signed cluster
"""
import os
import uuid
from unittest import skipUnless

import requests
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail, CaseHasNonFileIocs
from connectors.contrib.elastic_siem import service
from connectors.contrib.elastic_siem.connector import ElasticSiemConnector
from connectors.base import CaseEvent
from mail_feeder.models import Mail
from url_process.models import URL

ES_URL = os.environ.get("ES_SIEM_TEST_URL")
API_KEY = os.environ.get("ES_SIEM_TEST_API_KEY", "dummy")
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
                            headers={"Authorization": f"ApiKey {API_KEY}"})

    def _get(self, case_id):
        self.session.post(f"{ES_URL}/{self.index}/_refresh", verify=VERIFY,
                          headers={"Authorization": f"ApiKey {API_KEY}"})
        return self.session.get(f"{ES_URL}/{self.index}/_doc/{case_id}", verify=VERIFY,
                                headers={"Authorization": f"ApiKey {API_KEY}"})

    def _count(self):
        self.session.post(f"{ES_URL}/{self.index}/_refresh", verify=VERIFY,
                          headers={"Authorization": f"ApiKey {API_KEY}"})
        resp = self.session.get(f"{ES_URL}/{self.index}/_count", verify=VERIFY,
                                headers={"Authorization": f"ApiKey {API_KEY}"})
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
            headers={"Authorization": f"ApiKey {API_KEY}"}).json()[self.index]["mappings"]["properties"]
        self.assertEqual(mapping["related"]["properties"]["ip"]["type"], "ip")
        self.assertEqual(mapping["suspicious"]["properties"]["verdict"]["type"], "keyword")
        self.assertEqual(mapping["@timestamp"]["type"], "date")
