import io
import os
import tempfile
from unittest import mock

import pybreaker
import requests
from celery.exceptions import Retry
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

import settings.config as settings_config
from ai_model.models import AiAssessment
from ai_model.taxonomy import FOLDERS
from case_handler.models import Case, CaseHasFileOrMail
from common.http_client import BREAKERS
from common.storage import FakeObjectStore, StoreError
from connectors.base import ProviderResult, Schedule
from connectors.contrib.ai_model import connector as module
from connectors.contrib.ai_model import mailtext
from connectors.contrib.ai_model.connector import AiModelConnector, result_from_server
from connectors.contrib.ai_model.tests.test_mailtext import GOOD, build_tar
from connectors.models import ConnectorDelivery, ConnectorState
from connectors.providers import ProviderUnavailable, queue_provider_analysis
from connectors.registry import ConnectorRegistry, registry
from connectors.tasks import run_provider_analysis
from connectors.tests.test_provider_dispatch import make_mail_case
from cortex_job.models import CaseAnalyzerJob
from file_process.models import File
from hash_process.models import Hash
from mail_feeder.models import Mail, MailArchive

CONFIG = {"url": "http://ai_inference:8090", "token": "s3cret-token", "timeout_seconds": 9}
# The classes the inference server emits (Analyzers/AIMailAnalyzer/mail_analysis.py).
SERVER_CLASSES = ("SAFE", "UNWANTED", "DANGEROUS", "INCONCLUSIVE")


def payload(klass="SAFE", score=2.0, confidence=0.9, sub_class="HAM", tier=None):
    """The shape POST /v2/models/ai_mail/classify answers with (inference_server/v2.py)."""
    return {
        "results": {"active": {
            "version": "v0", "class": klass, "score": score, "confidence": confidence,
            "probabilities": {"SAFE": "5.00%", "UNWANTED": "10.00%", "DANGEROUS": "85.00%"},
            "sub_class": sub_class, "sub_class_confidence": 0.7,
            "sub_probabilities": {"CLASSIC_PHISHING": "70.00%"},
            "contributing_phrases": [["verify", 0.3]], "tier": tier, "similar_cases": [],
        }},
        "campaign_embedding": "[0.1, 0.2]", "campaign_embedding_version": "cmp-e1", "latency_ms": 12,
    }


class ManifestTest(SimpleTestCase):
    def test_manifest(self):
        m = AiModelConnector.manifest
        m.validate()
        self.assertEqual((m.name, m.provides, m.enabled_by_default), ("ai_model", "mail_ai", False))
        self.assertEqual((m.version, m.category, m.events), ("1.0.0", "AI", ("case_finalised",)))
        self.assertEqual({f.key: f.type for f in m.config_schema}["token"], "secret")

    def test_config_schema(self):
        fields = {f.key: f for f in AiModelConnector.manifest.config_schema}
        self.assertEqual(set(fields), {"url", "token", "timeout_seconds", "imap_host", "imap_port", "imap_user",
                                       "imap_password", "imap_use_ssl", "imap_folders",
                                       "retrain_enabled", "retrain_interval_days"})
        self.assertEqual((fields["url"].type, fields["url"].default, fields["url"].required),
                         ("url", "http://ai_inference:8090", True))
        self.assertTrue(fields["token"].required)
        self.assertEqual((fields["timeout_seconds"].type, fields["timeout_seconds"].default), ("int", 20))
        self.assertEqual({k: (fields[k].type, fields[k].default, fields[k].required) for k in (
            "imap_host", "imap_port", "imap_user", "imap_password", "imap_use_ssl")}, {
            "imap_host": ("str", None, False), "imap_port": ("int", 993, False),
            "imap_user": ("str", None, False), "imap_password": ("secret", None, False),
            "imap_use_ssl": ("bool", True, False)})
        self.assertEqual((fields["imap_folders"].type, fields["imap_folders"].default),
                         ("str", ",".join(FOLDERS)))
        self.assertEqual((fields["retrain_enabled"].type, fields["retrain_enabled"].default), ("bool", False))
        self.assertEqual((fields["retrain_interval_days"].type, fields["retrain_interval_days"].default),
                         ("int", 30))
        self.assertEqual(AiModelConnector.manifest.schedules, (Schedule("label-sync", 86400),))

    def test_the_imap_password_is_overlaid_from_vault(self):
        from settings.config import SECRET_FIELDS
        registry.discover()
        self.assertIn("imap_password", SECRET_FIELDS["integrations.ai_model"])

    def test_registered_as_a_builtin(self):
        registry.discover()
        self.assertIn("ai_model", registry.names())
        self.assertEqual(registry.providers("mail_ai"), ["ai_model"])


class ResultMappingTest(SimpleTestCase):
    def test_result_mapping_rounds_like_the_legacy_parser(self):
        r = result_from_server(payload(klass="DANGEROUS", score=7.4, confidence=0.815, sub_class="CLASSIC_PHISHING"))
        self.assertEqual((r.result, r.score, r.confidence, r.category), ("DANGEROUS", 7, 82, "Classic_phishing"))
        self.assertEqual((r.model_version, r.reason), ("v0", ""))

    def test_assessment_carries_the_full_server_answer_under_model_field_names(self):
        a = result_from_server(payload(klass="DANGEROUS", sub_class="CLASSIC_PHISHING")).assessment
        self.assertEqual(set(a), {
            "sub_class", "probabilities", "sub_probabilities", "tier", "contributing_phrases",
            "similar_cases", "campaign_embedding", "embedding_version", "latency_ms",
        })
        self.assertTrue(set(a) <= {f.name for f in AiAssessment._meta.get_fields()})
        self.assertEqual((a["sub_class"], a["embedding_version"], a["latency_ms"]), ("CLASSIC_PHISHING", "cmp-e1", 12))
        self.assertEqual(a["campaign_embedding"], "[0.1, 0.2]")
        self.assertEqual(a["probabilities"]["DANGEROUS"], "85.00%")
        self.assertEqual(a["contributing_phrases"], [["verify", 0.3]])

    def test_a_null_tier_is_stored_as_empty_text(self):
        self.assertEqual(result_from_server(payload()).assessment["tier"], "")
        self.assertEqual(result_from_server(payload(tier="T1")).assessment["tier"], "T1")

    def test_every_server_class_is_one_the_model_stores(self):
        for klass in SERVER_CLASSES:
            with self.subTest(klass=klass):
                self.assertIn(result_from_server(payload(klass=klass)).result, AiAssessment.Result.values)

    def test_long_sub_classes_are_cut_to_the_column_widths(self):
        r = result_from_server(payload(sub_class="x" * 80))
        self.assertEqual(len(r.category), 20)
        self.assertEqual(len(r.assessment["sub_class"]), 32)


class HealthCheckTest(SimpleTestCase):
    def check(self, config, ready, mismatch=None, synced=True):
        with mock.patch.object(module, "AiInferenceClient") as client_class, \
                mock.patch.object(module.serversync, "server_matches", return_value=synced), \
                mock.patch.object(module, "collection_mismatch", return_value=mismatch) as check:
            client_class.return_value.ready.return_value = ready
            status = AiModelConnector(config).health_check()
        check.assert_called_once_with("suspicious_mails")
        return status, client_class

    def test_the_collection_check_builds_no_profile(self):
        # SimpleTestCase refuses queries: current_profile() reads the allow-list from the database.
        with mock.patch("ai_model.campaign_profile.current_profile", side_effect=AssertionError("profile")):
            status, _ = self.check(CONFIG, (True, "ready"), "Cleanup watches 'a'.")
        self.assertEqual(status.detail, "ready. Cleanup watches 'a'.")

    def test_a_collection_mismatch_is_appended_without_changing_ok(self):
        sentence = "Cleanup watches 'a'."
        status, _ = self.check(CONFIG, (True, "ready, token accepted"), sentence)
        self.assertEqual((status.ok, status.detail), (True, "ready, token accepted. Cleanup watches 'a'."))
        status, _ = self.check(CONFIG, (False, "not ready (HTTP 503)"), sentence)
        self.assertEqual((status.ok, status.detail), (False, "not ready (HTTP 503). Cleanup watches 'a'."))
        status, _ = self.check({"url": "http://x"}, (True, ""), sentence)
        self.assertEqual((status.ok, status.detail), (False, "token not configured. Cleanup watches 'a'."))

    def test_no_mismatch_leaves_the_detail_as_it_was(self):
        status, _ = self.check(CONFIG, (True, "ready, token accepted"))
        self.assertEqual(status.detail, "ready, token accepted")

    def test_a_failing_collection_check_does_not_break_the_health_check(self):
        with mock.patch.object(module, "AiInferenceClient") as client_class, \
                mock.patch.object(module, "collection_mismatch", side_effect=RuntimeError("db down")), \
                self.assertLogs("connectors.contrib.ai_model", "DEBUG") as logs:
            client_class.return_value.ready.return_value = (True, "ready, token accepted")
            status = AiModelConnector(CONFIG).health_check()
        self.assertEqual((status.ok, status.detail), (True, "ready, token accepted"))
        self.assertIn("RuntimeError", logs.output[0])
        self.assertNotIn("db down", logs.output[0])

    def test_a_registry_and_server_that_differ_are_named(self):
        status, _ = self.check(CONFIG, (True, "ready, token accepted"), synced=False)
        self.assertEqual((status.ok, status.detail),
                         (True, "ready, token accepted. registry and server differ"))

    def test_health_check_ok_and_not_ok(self):
        status, client_class = self.check(CONFIG, (True, "ready, token accepted"))
        self.assertEqual((status.ok, status.detail), (True, "ready, token accepted"))
        client_class.assert_called_once_with("http://ai_inference:8090", "s3cret-token", 9.0)
        status, _ = self.check(CONFIG, (False, "not ready (HTTP 503)"))
        self.assertEqual((status.ok, status.detail), (False, "not ready (HTTP 503)"))

    def test_a_bad_saved_url_is_not_ok_without_any_request(self):
        for url in ("file:///etc/passwd", "http://user:pw@host"):
            with self.subTest(url=url):
                status, client_class = self.check({"url": url, "token": "s3cret-token"}, (True, ""))
                self.assertEqual((status.ok, status.detail), (False, "url is not a valid http(s) URL"))
                client_class.assert_not_called()

    def test_a_missing_token_is_not_ok_without_any_request(self):
        status, client_class = self.check({"url": "http://x"}, (True, ""))
        self.assertFalse(status.ok)
        self.assertIn("token", status.detail)
        client_class.assert_not_called()

    def test_defaults_apply_when_url_and_timeout_are_unset(self):
        _, client_class = self.check({"token": "s3cret-token"}, (True, ""))
        client_class.assert_called_once_with("http://ai_inference:8090", "s3cret-token", 20.0)


class AnalyzeTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="ai", password="x")
        mail = Mail.objects.create(subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m1")
        self.case = Case.objects.create(description="", reporter=user)
        self.case.fileOrMail = CaseHasFileOrMail.objects.create(case=self.case, mail=mail)
        self.case.save(update_fields=["fileOrMail"])
        file = File.objects.create(linked_hash=Hash.objects.create(value="h1"), tmp_path="mail.tar.gz")
        self.archive = MailArchive.objects.create(mail=mail, archive=file)
        self.connector = AiModelConnector(CONFIG)
        # No real object store in unit tests: an empty one means "not found", so the tar is read.
        patcher = mock.patch.object(mailtext, "get_store", return_value=FakeObjectStore())
        patcher.start()
        self.addCleanup(patcher.stop)

    def analyze(self, body="the mail", classify=None):
        """Run analyze with the archive read and the HTTP call stubbed."""
        with mock.patch.object(module, "read_archive_body", return_value=body) as read, \
                mock.patch.object(module.AiInferenceClient, "classify", **(classify or {"return_value": payload()})) as call:
            result = self.connector.analyze("mail_ai", self.case.id)
        return result, read, call

    def test_a_good_answer_is_mapped(self):
        result, read, call = self.analyze(classify={"return_value": payload("DANGEROUS", 7.4, 0.815, "WHALING")})
        read.assert_called_once_with(self.archive)
        call.assert_called_once_with("the mail", exclude_case_ids=[self.case.id])
        self.assertEqual((result.result, result.score, result.confidence, result.category),
                         ("DANGEROUS", 7, 82, "Whaling"))

    def test_the_body_comes_from_the_stored_archive_file(self):
        with tempfile.TemporaryDirectory() as media, override_settings(MEDIA_ROOT=media):
            self.archive.archive.file_path = SimpleUploadedFile("mail.tar.gz", build_tar(GOOD))
            self.archive.archive.save()
            with mock.patch.object(module.AiInferenceClient, "classify", return_value=payload()) as call:
                result = self.connector.analyze("mail_ai", self.case.id)
        call.assert_called_once_with(GOOD["m1.txt"].decode(), exclude_case_ids=[self.case.id])
        self.assertEqual(result.result, "SAFE")

    def test_the_client_is_built_from_the_connector_config(self):
        with mock.patch.object(module, "read_archive_body", return_value="b"), \
                mock.patch.object(module, "AiInferenceClient") as client_class:
            client_class.return_value.classify.return_value = payload()
            self.connector.analyze("mail_ai", self.case.id)
        client_class.assert_called_once_with("http://ai_inference:8090", "s3cret-token", 9.0)

    def test_a_4xx_becomes_an_inconclusive_result_and_never_trips_the_breaker(self):
        breaker = pybreaker.CircuitBreaker(fail_max=1, reset_timeout=60)
        for _ in range(3):
            with breaker.calling():  # as connectors.tasks.run_provider_analysis wraps analyze
                result, _, _ = self.analyze(classify={"side_effect": ValueError("HTTP 422: bad body")})
        self.assertEqual(breaker.current_state, "closed")
        self.assertEqual(result, ProviderResult(
            "INCONCLUSIVE", 0, 0, "No subclass found", "", {}, reason="HTTP 422: bad body"))

    def test_provider_unavailable_propagates_with_its_retry_flag(self):
        for retryable in (True, False):
            with self.subTest(retryable=retryable):
                with self.assertRaises(ProviderUnavailable) as caught:
                    self.analyze(classify={"side_effect": ProviderUnavailable("down", retryable)})
                self.assertEqual(caught.exception.retryable, retryable)

    def test_a_value_error_outside_the_http_call_is_not_swallowed(self):
        with self.assertRaises(ValueError):
            self.analyze(classify={"return_value": payload(score="abc")})

    def test_empty_or_missing_body_gives_inconclusive_with_a_reason(self):
        result, _, call = self.analyze(body=None)
        self.assertEqual(result, ProviderResult(
            "INCONCLUSIVE", 0, 0, "No subclass found", "", {}, reason="archive_unreadable"))
        call.assert_not_called()

    def test_a_case_without_a_mail_archive_is_inconclusive(self):
        MailArchive.objects.all().delete()
        result, read, call = self.analyze()
        self.assertEqual((result.result, result.reason), ("INCONCLUSIVE", "no_mail_archive"))
        read.assert_not_called()
        call.assert_not_called()

    def test_a_case_without_a_mail_is_inconclusive(self):
        other = Case.objects.create(description="", reporter=self.case.reporter)
        with mock.patch.object(module.AiInferenceClient, "classify") as call:
            result = self.connector.analyze("mail_ai", other.id)
        self.assertEqual((result.result, result.reason), ("INCONCLUSIVE", "no_mail_archive"))
        call.assert_not_called()


class RejectedTokenEndToEndTest(TestCase):
    """The real connector and client, only the HTTP layer faked, driven by the Celery task."""

    def setUp(self):
        private = ConnectorRegistry()
        private.register(AiModelConnector)
        for target in ("connectors.providers.registry", "connectors.delivery.registry"):
            patcher = mock.patch(target, private)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(private, "instantiate", return_value=AiModelConnector(CONFIG))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.breaker = pybreaker.CircuitBreaker(fail_max=5, reset_timeout=60)
        patcher = mock.patch.dict(BREAKERS, {"ai_model": self.breaker})
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("tasp.tasks.reconcile_case")
        self.reconcile = patcher.start()
        self.addCleanup(patcher.stop)
        ConnectorState.objects.create(name="ai_model", enabled=True)
        self.case, _ = make_mail_case(n=50)

    def run_with_status(self, status, detail="invalid or missing bearer token"):
        response = mock.Mock(status_code=status, text=detail)
        response.json.return_value = {"detail": detail}
        session = mock.Mock()
        session.post.return_value = response
        with mock.patch("connectors.contrib.ai_model.client.make_session", return_value=session), \
                mock.patch.object(module, "read_archive_body", return_value="the mail"):
            job = queue_provider_analysis(self.case, "mail_ai")  # the on_commit enqueue never fires here
            with self.captureOnCommitCallbacks(execute=True):
                run_provider_analysis.apply(args=(self.case.id, "mail_ai", job.id))
        job.refresh_from_db()
        self.case.refresh_from_db()
        return job, session

    def test_a_rejected_token_fails_the_row_at_once_and_says_why(self):
        job, session = self.run_with_status(401)
        self.assertEqual(session.post.call_count, 1)  # no retry
        self.assertEqual(job.status, CaseAnalyzerJob.STATUS_FAILURE)
        self.assertEqual(self.case.results_ai, "Inconclusive")
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual(
            (delivery.connector, delivery.event, delivery.status, delivery.attempt),
            ("ai_model", "analyze", ConnectorDelivery.STATUS_FAILED, 1),
        )
        self.assertIn("rejected the token", delivery.error)
        self.assertIn("HTTP 401", delivery.error)
        self.assertNotIn(CONFIG["token"], delivery.error)
        self.reconcile.delay.assert_called_once_with(self.case.id)
        self.assertEqual(self.breaker.fail_counter, 1)  # a refused setup counts toward the breaker

    def test_a_422_closes_the_row_as_a_failure_without_tripping_the_breaker(self):
        # A 422 detail can echo the request, so the mail: only the status is kept.
        with self.assertLogs("connectors", "WARNING") as logs:
            job, _ = self.run_with_status(422, "bad body")
        self.assertEqual(job.status, CaseAnalyzerJob.STATUS_FAILURE)
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual(delivery.status, ConnectorDelivery.STATUS_FAILED)
        self.assertIn("no model_version (inference server refused the request (HTTP 422)", delivery.error)
        self.assertTrue(any("HTTP 422" in line and "provider failed" in line for line in logs.output))
        self.assertNotIn("bad body", "\n".join(logs.output))
        self.assertNotIn("bad body", delivery.error)
        self.assertEqual(self.breaker.fail_counter, 0)
        self.assertFalse(AiAssessment.objects.filter(case=self.case).exists())


class ArchiveGoneBetweenAttemptsTest(TestCase):
    """The drill failure: the work dir is wiped after the handoff, so a retry must still find the mail."""

    MAIL = "261007071836-7a54e9fcb2f6"
    # The store copy differs from the tar's text, so the assertions can tell which one was read.
    STORE_TEXT = b"STORE COPY: " + GOOD["m1.txt"]

    def setUp(self):
        private = ConnectorRegistry()
        private.register(AiModelConnector)
        for target in ("connectors.providers.registry", "connectors.delivery.registry"):
            patcher = mock.patch(target, private)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(private, "instantiate", return_value=AiModelConnector(CONFIG))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.dict(BREAKERS, {"ai_model": pybreaker.CircuitBreaker(fail_max=5, reset_timeout=60)})
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("tasp.tasks.reconcile_case")
        self.reconcile = patcher.start()
        self.addCleanup(patcher.stop)
        ConnectorState.objects.create(name="ai_model", enabled=True)

        self.case, self.archive = make_mail_case(n=51)
        Mail.objects.filter(pk=self.archive.mail_id).update(mail_id=self.MAIL)
        self.workdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.workdir.cleanup)
        self.tar_path = os.path.join(self.workdir.name, "mail.tar.gz")
        with open(self.tar_path, "wb") as handle:
            handle.write(build_tar(GOOD))
        File.objects.filter(pk=self.archive.archive_id).update(tmp_path=self.tar_path)

        self.store = FakeObjectStore()  # the durable copy the mail feeder uploaded
        patcher = mock.patch.object(mailtext, "get_store", return_value=self.store)
        patcher.start()
        self.addCleanup(patcher.stop)
        real_get_section = settings_config.get_section  # only storage.s3 is faked: the Cortex config is read too
        patcher = mock.patch(
            "settings.config.get_section",
            side_effect=lambda name, *a, **k: (
                {"feeder_bucket": "suspicious-feeder"} if name == "storage.s3" else real_get_section(name, *a, **k)
            ),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def upload(self, bucket, prefix):
        self.store.ensure_bucket(bucket)
        for name, data in ((".txt", self.STORE_TEXT), (".headers", GOOD["m1.headers"])):
            self.store.put(bucket, f"{prefix}{self.MAIL}/m1{name}", io.BytesIO(data))

    def drill(self):
        """Attempt 1: server down -> retry. The work dir is wiped. Attempt 2: server up."""
        down = requests.ConnectionError("ai_inference down")
        up = mock.Mock(status_code=200)
        up.json.return_value = payload("DANGEROUS", 7.4, 0.815, "CLASSIC_PHISHING")
        session = mock.Mock()
        session.post.side_effect = [down, up]
        with mock.patch("connectors.contrib.ai_model.client.make_session", return_value=session):
            job = queue_provider_analysis(self.case, "mail_ai")  # the on_commit enqueue never fires here
            with self.assertRaises(Retry):  # attempt 1: server down; eager mode propagates Retry
                run_provider_analysis.apply(args=(self.case.id, "mail_ai", job.id), retries=0)
            job.refresh_from_db()
            self.assertEqual(job.status, CaseAnalyzerJob.STATUS_INPROGRESS)

            os.remove(self.tar_path)  # what tasp/cron/fetch_emails.py does once the handoff ends
            with self.captureOnCommitCallbacks(execute=True):
                run_provider_analysis.apply(args=(self.case.id, "mail_ai", job.id), retries=1)

        job.refresh_from_db()
        self.case.refresh_from_db()
        self.assertEqual(job.status, CaseAnalyzerJob.STATUS_SUCCESS)
        for call in session.post.call_args_list:  # both attempts sent the store's copy, not the tar's
            self.assertEqual(call.kwargs["json"]["mail_body"], self.STORE_TEXT.decode())
        self.assertEqual((self.case.results_ai, self.case.score_ai, self.case.confidence_ai),
                         ("Dangerous", 7, 82))
        self.assertEqual(self.case.ai_assessment.result, "DANGEROUS")
        self.assertEqual(self.case.ai_assessment.sub_class, "CLASSIC_PHISHING")
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual((delivery.status, delivery.attempt, delivery.error), ("success", 2, ""))
        self.reconcile.delay.assert_called_once_with(self.case.id)

    def test_a_retry_after_the_work_dir_is_wiped_still_classifies_the_mail(self):
        self.upload("haruto-submission-261007071836", "")  # legacy: a bucket per submission
        MailArchive.objects.filter(pk=self.archive.pk).update(bucket_name="haruto-submission-261007071836")
        self.drill()

    def test_the_same_with_the_feeder_prefix_layout(self):
        self.upload("suspicious-feeder", "sub-1/")  # <submission_id>/<mail_id>/<ref>.txt
        MailArchive.objects.filter(pk=self.archive.pk).update(bucket_name="sub-1")
        self.drill()

    def test_the_same_with_a_submission_id_s3_cannot_name_a_bucket_after(self):
        submission = "Haruto.Sato_jp-submission-261007071836"  # the feeder keeps case and "_" in the id
        real_bucket_exists = self.store.bucket_exists

        def bucket_exists(bucket):  # S3 answers 400 to a bucket name it cannot hold, mapped to invalid
            if bucket != bucket.lower() or "_" in bucket:
                raise StoreError("invalid", "400 Bad Request", bucket=bucket)
            return real_bucket_exists(bucket)

        self.store.bucket_exists = bucket_exists
        self.upload("suspicious-feeder", f"{submission}/")
        MailArchive.objects.filter(pk=self.archive.pk).update(bucket_name=submission)
        self.drill()
