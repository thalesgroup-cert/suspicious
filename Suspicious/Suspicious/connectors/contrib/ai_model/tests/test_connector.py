import tempfile
from unittest import mock

import pybreaker
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from ai_model.models import AiAssessment
from case_handler.models import Case, CaseHasFileOrMail
from connectors.base import ProviderResult
from connectors.contrib.ai_model import connector as module
from connectors.contrib.ai_model.connector import AiModelConnector, result_from_server
from connectors.providers import ProviderUnavailable
from connectors.contrib.ai_model.tests.test_mailtext import GOOD, build_tar
from connectors.registry import registry
from file_process.models import File
from hash_process.models import Hash
from mail_feeder.models import Mail, MailArchive

CONFIG = {"url": "http://ai_inference:8090", "token": "tok", "timeout_seconds": 9}
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
        self.assertEqual((m.version, m.category, m.events), ("1.0.0", "AI", ()))
        self.assertEqual({f.key: f.type for f in m.config_schema}["token"], "secret")

    def test_config_schema(self):
        fields = {f.key: f for f in AiModelConnector.manifest.config_schema}
        self.assertEqual(set(fields), {"url", "token", "timeout_seconds"})
        self.assertEqual((fields["url"].type, fields["url"].default, fields["url"].required),
                         ("url", "http://ai_inference:8090", True))
        self.assertTrue(fields["token"].required)
        self.assertEqual((fields["timeout_seconds"].type, fields["timeout_seconds"].default), ("int", 20))

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
    def check(self, config, ready):
        with mock.patch.object(module, "AiInferenceClient") as client_class:
            client_class.return_value.ready.return_value = ready
            status = AiModelConnector(config).health_check()
        return status, client_class

    def test_health_check_ok_and_not_ok(self):
        status, client_class = self.check(CONFIG, (True, "ready, token accepted"))
        self.assertEqual((status.ok, status.detail), (True, "ready, token accepted"))
        client_class.assert_called_once_with("http://ai_inference:8090", "tok", 9.0)
        status, _ = self.check(CONFIG, (False, "not ready (HTTP 503)"))
        self.assertEqual((status.ok, status.detail), (False, "not ready (HTTP 503)"))

    def test_a_missing_token_is_not_ok_without_any_request(self):
        status, client_class = self.check({"url": "http://x"}, (True, ""))
        self.assertFalse(status.ok)
        self.assertIn("token", status.detail)
        client_class.assert_not_called()

    def test_defaults_apply_when_url_and_timeout_are_unset(self):
        _, client_class = self.check({"token": "tok"}, (True, ""))
        client_class.assert_called_once_with("http://ai_inference:8090", "tok", 20.0)


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

    def analyze(self, body="the mail", classify=None):
        """Run analyze with the archive read and the HTTP call stubbed."""
        with mock.patch.object(module, "read_archive_body", return_value=body) as read, \
                mock.patch.object(module.AiInferenceClient, "classify", **(classify or {"return_value": payload()})) as call:
            result = self.connector.analyze("mail_ai", self.case.id)
        return result, read, call

    def test_a_good_answer_is_mapped(self):
        result, read, call = self.analyze(classify={"return_value": payload("DANGEROUS", 7.4, 0.815, "WHALING")})
        read.assert_called_once_with(self.archive)
        call.assert_called_once_with("the mail")
        self.assertEqual((result.result, result.score, result.confidence, result.category),
                         ("DANGEROUS", 7, 82, "Whaling"))

    def test_the_body_comes_from_the_stored_archive_file(self):
        with tempfile.TemporaryDirectory() as media, override_settings(MEDIA_ROOT=media):
            self.archive.archive.file_path = SimpleUploadedFile("mail.tar.gz", build_tar(GOOD))
            self.archive.archive.save()
            with mock.patch.object(module.AiInferenceClient, "classify", return_value=payload()) as call:
                result = self.connector.analyze("mail_ai", self.case.id)
        call.assert_called_once_with(GOOD["m1.txt"].decode())
        self.assertEqual(result.result, "SAFE")

    def test_the_client_is_built_from_the_connector_config(self):
        with mock.patch.object(module, "read_archive_body", return_value="b"), \
                mock.patch.object(module, "AiInferenceClient") as client_class:
            client_class.return_value.classify.return_value = payload()
            self.connector.analyze("mail_ai", self.case.id)
        client_class.assert_called_once_with("http://ai_inference:8090", "tok", 9.0)

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
