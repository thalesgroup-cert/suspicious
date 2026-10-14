"""Does every datum on a realistic case reach the SIEM? Builds a rich mail case,
delivers it through the real framework path to a real Elasticsearch, and checks
the stored document against what the database says is on the case.

Skipped unless ES_SIEM_TEST_URL is set (same variables as test_live_es).
Set ES_SIEM_SHOW_DOC=1 to print the stored document."""
import json
import os
import uuid
from io import StringIO
from unittest import mock, skipUnless

import requests
from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail
from connectors import delivery
from connectors.base import EVENT_CASE_FINALISED
from connectors.contrib.elastic_siem.connector import ElasticSiemConnector
from connectors.events import build_case_event
from connectors.models import ConnectorDelivery, ConnectorState
from domain_process.models import Domain
from file_process.models import File
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import (
    ArtifactIsDomain, ArtifactIsHash, ArtifactIsIp, ArtifactIsUrl, Mail, MailArtifact, MailAttachment,
)
from url_process.models import URL

ES_URL = os.environ.get("ES_SIEM_TEST_URL")
API_KEY = os.environ.get("ES_SIEM_TEST_API_KEY", "dummy")
ADMIN_KEY = os.environ.get("ES_SIEM_TEST_ADMIN_KEY", API_KEY)
VERIFY = os.environ.get("ES_SIEM_TEST_VERIFY", "true").lower() != "false"
ADMIN = {"Authorization": f"ApiKey {ADMIN_KEY}"}

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def _artifact(mail, kind, model, link_field, **fields):
    artifact = MailArtifact.objects.create(mail=mail, artifact_type=kind)
    link = model.objects.create(artifact=artifact, **{link_field: fields[link_field]})
    setattr(artifact, f"artifactIs{kind}", link)
    artifact.save()
    return artifact


@skipUnless(ES_URL, "set ES_SIEM_TEST_URL to run against a real Elasticsearch")
class FullCaseCompletenessTests(TestCase):
    def setUp(self):
        self.index = f"suspicious-siem-test-{uuid.uuid4().hex[:8]}"
        self.config = {"url": ES_URL, "api_key": API_KEY, "index": self.index,
                       "verify_tls": VERIFY, "ui_base_url": "https://sus.meridian.example"}
        self.addCleanup(lambda: requests.delete(f"{ES_URL}/{self.index}", verify=VERIFY, headers=ADMIN))

    def _mail_case(self):
        user = User.objects.create_user("jordan.kim", "jordan.kim@meridian.example", "pw")
        case = Case.objects.create(
            description="Reported by Jordan: looks like a fake invoice", reporter=user,
            results="Dangerous", final_score=9.4, final_confidence=91,
            verdict_explanation={"band": "Dangerous", "decisive_rule": "embedded-ioc-escalation"},
        )
        mail = Mail.objects.create(
            subject="Urgent: invoice 4411 overdue", reportedBy="jordan.kim@meridian.example",
            date=timezone.now(), mail_id="<4411.abc@acme-pay.test>",
            mail_from="Accounts <billing@acme-pay.test>",
            to="victim@meridian.example, finance@meridian.example", cc="boss@meridian.example",
            reporterNote="please check",
        )
        # The five IOC kinds a phishing mail yields.
        self.url_a = URL.objects.create(address="http://acme-pay.test/login?id=4411")
        self.url_b = URL.objects.create(address="https://203.0.113.50/pay")
        _artifact(mail, "Url", ArtifactIsUrl, "url", url=self.url_a)
        _artifact(mail, "Url", ArtifactIsUrl, "url", url=self.url_b)
        _artifact(mail, "Ip", ArtifactIsIp, "ip", ip=IP.objects.create(address="198.51.100.23"))
        _artifact(mail, "Hash", ArtifactIsHash, "hash", hash=Hash.objects.create(value=MD5, hashtype="md5"))
        _artifact(mail, "Domain", ArtifactIsDomain, "domain", domain=Domain.objects.create(value="acme-pay.test"))
        # An attachment whose own hash is the strongest IOC on the case.
        attachment_hash = Hash.objects.create(value=SHA256, hashtype="sha256 hash")
        attachment = File.objects.create(linked_hash=attachment_hash, file_path="files/invoice_4411.pdf",
                                         tmp_path="/tmp/x", other_names="", filetype="PDF", size=4096)
        MailAttachment.objects.create(mail=mail, file=attachment)
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save()
        return case

    def _file_case(self):
        user = User.objects.get(username="jordan.kim")
        case = Case.objects.create(description="d", reporter=user, results="Suspicious",
                                   final_score=6.0, final_confidence=70)
        sha1 = Hash.objects.create(value=SHA1, hashtype="SHA-1")
        upload = File.objects.create(linked_hash=sha1, file_path="files/dropper.exe",
                                     tmp_path="/tmp/y", other_names="", filetype="PE", size=1)
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, file=upload)
        case.save()
        return case

    def _deliver_and_fetch(self, case):
        ConnectorState.objects.update_or_create(name="elastic_siem", defaults={"enabled": True})
        payload = build_case_event(EVENT_CASE_FINALISED, case).to_dict()
        with mock.patch("connectors.registry.ConnectorRegistry.instantiate",
                        lambda registry, name: ElasticSiemConnector(self.config)):
            delivery.deliver_now("elastic_siem", EVENT_CASE_FINALISED, payload)
        self.assertEqual(ConnectorDelivery.objects.get(connector="elastic_siem", case_id=case.pk).status,
                         ConnectorDelivery.STATUS_SUCCESS)
        requests.post(f"{ES_URL}/{self.index}/_refresh", verify=VERIFY, headers=ADMIN)
        source = requests.get(f"{ES_URL}/{self.index}/_doc/{case.pk}", verify=VERIFY, headers=ADMIN).json()["_source"]
        if os.environ.get("ES_SIEM_SHOW_DOC"):
            print("\n" + json.dumps(source, indent=2, sort_keys=True))
        return source

    def test_mail_case_every_datum_is_sent(self):
        case = self._mail_case()
        doc = self._deliver_and_fetch(case)

        # verdict
        self.assertEqual(doc["suspicious"]["case_id"], case.pk)
        self.assertEqual(doc["suspicious"]["verdict"], "Dangerous")
        self.assertEqual(doc["suspicious"]["score"], 9.4)
        self.assertEqual(doc["suspicious"]["confidence"], 91)
        self.assertEqual(doc["suspicious"]["decisive_rule"], "embedded-ioc-escalation")
        self.assertEqual(doc["suspicious"]["url"], f"https://sus.meridian.example/investigation?open={case.pk}")
        self.assertEqual(doc["event"]["risk_score"], 9.4)
        self.assertEqual(doc["event"]["action"], "case_finalised")
        # mail
        self.assertEqual(doc["email"]["subject"], "Urgent: invoice 4411 overdue")
        self.assertEqual(doc["email"]["from"]["address"], ["billing@acme-pay.test"])
        self.assertEqual(doc["email"]["to"]["address"], ["victim@meridian.example", "finance@meridian.example"])
        self.assertEqual(doc["email"]["cc"]["address"], ["boss@meridian.example"])
        self.assertEqual(doc["email"]["message_id"], "<4411.abc@acme-pay.test>")
        # IOCs: every URL / IP / domain / hash the database holds for this mail
        self.assertEqual(sorted(doc["url"]["original"]), sorted([self.url_a.address, self.url_b.address]))
        self.assertEqual(sorted(doc["related"]["ip"]), ["198.51.100.23", "203.0.113.50"])
        self.assertEqual(doc["related"]["hosts"], ["acme-pay.test"])
        self.assertIn(MD5, doc["related"]["hash"])
        self.assertEqual(doc["file"]["hash"]["md5"], [MD5])
        # the attachment: name and its own hash
        self.assertEqual(doc["file"]["name"], ["invoice_4411.pdf"])
        self.assertIn(SHA256, doc["related"]["hash"])
        self.assertEqual(doc["file"]["hash"]["sha256"], [SHA256])

    def test_uploaded_file_case_sends_name_and_hash(self):
        self._mail_case()  # creates the user
        case = self._file_case()
        doc = self._deliver_and_fetch(case)
        self.assertEqual(doc["file"]["name"], ["dropper.exe"])
        self.assertEqual(doc["file"]["hash"]["sha1"], [SHA1])
        self.assertEqual(doc["related"]["hash"], [SHA1])
        self.assertNotIn("email", doc)

    def test_nothing_private_is_sent(self):
        case = self._mail_case()
        stored = json.dumps(self._deliver_and_fetch(case))
        for private in ("jordan.kim", "Reported by Jordan", "please check", "reportedBy"):
            self.assertNotIn(private, stored)


@skipUnless(ES_URL, "set ES_SIEM_TEST_URL to run against a real Elasticsearch")
class BackfillAndLifecycleTests(TestCase):
    def setUp(self):
        self.index = f"suspicious-siem-test-{uuid.uuid4().hex[:8]}"
        self.config = {"url": ES_URL, "api_key": API_KEY, "index": self.index, "verify_tls": VERIFY}
        self.user = User.objects.create_user("jordan.kim", "jordan.kim@meridian.example", "pw")
        self.addCleanup(lambda: requests.delete(f"{ES_URL}/{self.index}", verify=VERIFY, headers=ADMIN))

    def _docs(self):
        requests.post(f"{ES_URL}/{self.index}/_refresh", verify=VERIFY, headers=ADMIN)
        hits = requests.post(f"{ES_URL}/{self.index}/_search", json={"size": 100}, verify=VERIFY,
                             headers=ADMIN).json()["hits"]["hits"]
        return {int(h["_id"]): h["_source"] for h in hits}

    def _reindex(self, *args, **kwargs):
        out = StringIO()
        module = "connectors.management.commands.reindex_siem"
        with mock.patch(f"{module}.get_section", return_value=self.config), \
             mock.patch(f"{module}.get_state", return_value=mock.Mock(enabled=True)):
            call_command("reindex_siem", *args, stdout=out, **kwargs)
        return out.getvalue()

    def _cases(self):
        return {
            results: Case.objects.create(description=results, reporter=self.user, results=results, final_score=5.0)
            for results in ("Dangerous", "Suspicious", "Inconclusive", "Safe", "Failure")
        }

    def test_reindex_backfills_only_cases_at_or_above_min_verdict(self):
        cases = self._cases()

        self.assertIn("2 sent, 3 skipped, 0 failed", self._reindex())
        docs = self._docs()
        self.assertEqual(set(docs), {cases["Dangerous"].pk, cases["Suspicious"].pk})
        self.assertEqual({d["event"]["action"] for d in docs.values()}, {"reindex"})

        # Re-running is idempotent: same documents, not duplicates.
        self._reindex()
        self.assertEqual(len(self._docs()), 2)

    def test_reindex_dry_run_and_min_verdict_override(self):
        self._cases()
        self.assertIn("2 would be sent", self._reindex(dry_run=True))
        self.assertEqual(self._docs() if requests.head(f"{ES_URL}/{self.index}", verify=VERIFY,
                                                       headers=ADMIN).status_code == 200 else {}, {})
        self.assertIn("4 sent", self._reindex(min_verdict="Safe"))  # Failure has no rank
        self.assertEqual(len(self._docs()), 4)

    def test_lifecycle_forward_then_downgrade_then_upgrade(self):
        case = Case.objects.create(description="d", reporter=self.user, results="Dangerous", final_score=9.0,
                                   final_confidence=90)
        connector = ElasticSiemConnector(self.config)
        event = lambda name: build_case_event(name, case)  # noqa: E731

        connector.on_case_finalised(event("case_finalised"))
        self.assertEqual(self._docs()[case.pk]["suspicious"]["verdict"], "Dangerous")

        case.results, case.final_score = "Safe", 1.0
        case.save()
        connector.on_case_modified(event("case_modified"))
        doc = self._docs()[case.pk]
        self.assertEqual((doc["suspicious"]["verdict"], doc["event"]["risk_score"]), ("Safe", 1.0))
        self.assertEqual(doc["event"]["action"], "case_modified")

        case.results, case.final_score = "Suspicious", 6.0
        case.save()
        connector.on_case_modified(event("case_modified"))
        doc = self._docs()[case.pk]
        self.assertEqual((doc["suspicious"]["verdict"], doc["event"]["risk_score"]), ("Suspicious", 6.0))
        self.assertEqual(len(self._docs()), 1)
