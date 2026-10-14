import fnmatch
import json
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from case_handler.models import (
    Case, CaseHasFileOrMail, CaseHasNonFileIocs, ObservableGroup, ObservableGroupArtifact,
)
from connectors.contrib.elastic_siem import service
from domain_process.models import Domain
from file_process.models import File
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import ArtifactIsHash, Mail, MailArtifact, MailAttachment
from url_process.models import URL

NOW = timezone.now()


def fake_response(status=200, body=None, text=None):
    response = mock.Mock(status_code=status)
    response.json.return_value = body if body is not None else {}
    response.text = text if text is not None else json.dumps(body or {})
    return response


class DefaultIndexNameTests(SimpleTestCase):
    """The default index must be visible to Elastic Security's default data view
    (`logs-*`) without a Kibana change, yet must not match the built-in
    `logs-*-*` data-stream template, which rejects overwrite-by-id writes."""

    def test_matches_security_default_pattern(self):
        self.assertTrue(fnmatch.fnmatchcase(service.DEFAULT_INDEX, "logs-*"))

    def test_does_not_match_the_logs_data_stream_template(self):
        self.assertFalse(fnmatch.fnmatchcase(service.DEFAULT_INDEX, "logs-*-*"))


class VerdictFilterTests(SimpleTestCase):
    def test_ranks(self):
        rank = lambda results: service.case_rank(SimpleNamespace(results=results))  # noqa: E731
        self.assertEqual(rank("Safe"), 0)
        self.assertEqual(rank("AllowListed"), 0)
        self.assertEqual(rank("Inconclusive"), 1)
        self.assertEqual(rank("Suspicious"), 2)
        self.assertEqual(rank("Dangerous"), 3)

    def test_unchallenged_and_failure_have_no_rank(self):
        for results in ("Unchallenged", "Failure", "whatever"):
            self.assertIsNone(service.case_rank(SimpleNamespace(results=results)))

    def test_min_rank_defaults_to_suspicious(self):
        self.assertEqual(service.min_rank({}), 2)
        self.assertEqual(service.min_rank({"min_verdict": ""}), 2)
        self.assertEqual(service.min_rank({"min_verdict": None}), 2)

    def test_min_rank_for_each_known_verdict(self):
        expected = {"Safe": 0, "Inconclusive": 1, "Suspicious": 2, "Dangerous": 3}
        for name, rank in expected.items():
            self.assertEqual(service.min_rank({"min_verdict": name}), rank)

    def test_min_rank_unknown_verdict_raises(self):
        for value in ("Banana", "AllowListed", "Failure", "suspicious", 5, ["Dangerous"]):
            with self.assertRaises(ValueError):
                service.min_rank({"min_verdict": value})

    def test_is_forwardable_matrix(self):
        def forwardable(results, min_verdict):
            case = SimpleNamespace(results=results)
            return service.is_forwardable(case, {"min_verdict": min_verdict})

        for min_verdict, expected in {
            "Safe": {"Safe", "AllowListed", "Inconclusive", "Suspicious", "Dangerous"},
            "Inconclusive": {"Inconclusive", "Suspicious", "Dangerous"},
            "Suspicious": {"Suspicious", "Dangerous"},
            "Dangerous": {"Dangerous"},
        }.items():
            for results in ("Safe", "AllowListed", "Inconclusive", "Suspicious", "Dangerous"):
                self.assertEqual(forwardable(results, min_verdict), results in expected,
                                 (results, min_verdict))

    def test_unranked_is_never_forwardable_even_with_lowest_threshold(self):
        for results in ("Unchallenged", "Failure"):
            self.assertFalse(service.is_forwardable(SimpleNamespace(results=results), {"min_verdict": "Safe"}))


def _case(user, **kw):
    return Case.objects.create(description="d", reporter=user, **kw)


def _reload(case):
    return Case.objects.select_related(*service.CASE_RELATED).get(pk=case.pk)


class BuildDocumentTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", "alice@x.io", "pw")

    def _mail_case(self, **mail_kw):
        case = _case(self.user, results="Dangerous", final_score=9.2, final_confidence=88,
                     verdict_explanation={"decisive_rule": "embedded-ioc-escalation"})
        fields = dict(subject="Your invoice", reportedBy="r", date=NOW, mail_id="<m1@evil.test>",
                      mail_from="Bad Guy <bad@evil.test>", to="victim@corp.test, other@corp.test",
                      cc="Boss <boss@corp.test>, victim@corp.test")
        fields.update(mail_kw)
        mail = Mail.objects.create(**fields)
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save()
        return _reload(case)

    def test_core_fields(self):
        case = self._mail_case()
        doc = service.build_document(case, "case_finalised", now=NOW)

        self.assertEqual(doc["@timestamp"], NOW.isoformat())
        self.assertEqual(doc["event"]["kind"], "event")
        self.assertEqual(doc["event"]["category"], ["email", "threat"])
        self.assertEqual(doc["event"]["type"], ["info"])
        self.assertEqual(doc["event"]["module"], "suspicious")
        self.assertEqual(doc["event"]["dataset"], "suspicious.case")
        self.assertEqual(doc["event"]["action"], "case_finalised")
        self.assertEqual(doc["event"]["id"], str(case.pk))
        self.assertEqual(doc["event"]["risk_score"], 9.2)
        self.assertEqual(doc["event"]["created"], case.creation_date.isoformat())
        self.assertEqual(doc["suspicious"]["case_id"], case.pk)
        self.assertEqual(doc["suspicious"]["verdict"], "Dangerous")
        self.assertEqual(doc["suspicious"]["score"], 9.2)
        self.assertEqual(doc["suspicious"]["confidence"], 88)
        self.assertEqual(doc["suspicious"]["status"], case.status)
        self.assertEqual(doc["suspicious"]["decisive_rule"], "embedded-ioc-escalation")

    def test_mail_fields(self):
        doc = service.build_document(self._mail_case(), "case_finalised", now=NOW)
        self.assertEqual(doc["email"]["subject"], "Your invoice")
        self.assertEqual(doc["email"]["from"]["address"], ["bad@evil.test"])
        self.assertEqual(doc["email"]["to"]["address"], ["victim@corp.test", "other@corp.test"])

    def test_cc_recipients_and_message_id(self):
        doc = service.build_document(self._mail_case(), "case_finalised", now=NOW)
        self.assertEqual(doc["email"]["cc"]["address"], ["boss@corp.test", "victim@corp.test"])
        self.assertEqual(doc["email"]["message_id"], "<m1@evil.test>")

    def test_empty_cc_and_message_id_are_omitted(self):
        doc = service.build_document(self._mail_case(cc="", mail_id=""), "case_finalised", now=NOW)
        self.assertNotIn("cc", doc["email"])
        self.assertNotIn("message_id", doc["email"])

    def test_message_id_is_capped(self):
        doc = service.build_document(self._mail_case(mail_id="<" + "a" * 2000 + ">"), "case_finalised", now=NOW)
        self.assertEqual(len(doc["email"]["message_id"]), 512)

    def test_no_reporter_identity_anywhere(self):
        doc = json.dumps(service.build_document(self._mail_case(), "case_finalised", now=NOW))
        self.assertNotIn("alice@x.io", doc)
        self.assertNotIn("alice", doc)

    def test_mail_body_and_description_are_not_sent(self):
        case = self._mail_case(reporterNote="secret note")
        case.description = "private description"
        case.save()
        doc = json.dumps(service.build_document(_reload(case), "case_finalised", now=NOW))
        self.assertNotIn("secret note", doc)
        self.assertNotIn("private description", doc)

    def test_ui_link_only_with_base_url(self):
        case = self._mail_case()
        without = service.build_document(case, "case_finalised", now=NOW)
        self.assertNotIn("url", without["suspicious"])
        with_url = service.build_document(case, "case_finalised", ui_base_url="https://sus.corp/", now=NOW)
        self.assertEqual(with_url["suspicious"]["url"], f"https://sus.corp/investigation?open={case.pk}")

    def test_ioc_fields_from_non_file_ioc(self):
        case = _case(self.user, results="Suspicious")
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(
            case=case, url=URL.objects.create(address="http://phish.evil.test/login?x=1"),
        )
        case.save()
        doc = service.build_document(_reload(case), "case_finalised", now=NOW)
        self.assertEqual(doc["url"]["original"], ["http://phish.evil.test/login?x=1"])
        self.assertEqual(doc["related"]["hosts"], ["phish.evil.test"])
        self.assertNotIn("email", doc)

    def test_ip_hash_domain_from_observable_group(self):
        group = ObservableGroup.objects.create(label="g")
        ObservableGroupArtifact.objects.create(
            group=group, artifact_type="IP", ip=IP.objects.create(address="203.0.113.7"))
        ObservableGroupArtifact.objects.create(
            group=group, artifact_type="HASH",
            hash=Hash.objects.create(value="A" * 64, hashtype="sha256 hash"))
        ObservableGroupArtifact.objects.create(
            group=group, artifact_type="HASH",
            hash=Hash.objects.create(value="b" * 32, hashtype="MD5"))
        ObservableGroupArtifact.objects.create(
            group=group, artifact_type="HASH",
            hash=Hash.objects.create(value="c" * 40, hashtype="sha-1"))
        ObservableGroupArtifact.objects.create(
            group=group, artifact_type="HASH",
            hash=Hash.objects.create(value="d" * 20, hashtype="ssdeep"))
        ObservableGroupArtifact.objects.create(
            group=group, artifact_type="DOMAIN", domain=Domain.objects.create(value="Evil.Test"))
        case = _case(self.user, results="Dangerous", observable_group=group)

        doc = service.build_document(_reload(case), "case_finalised", now=NOW)

        self.assertEqual(doc["related"]["ip"], ["203.0.113.7"])
        self.assertEqual(doc["related"]["hosts"], ["evil.test"])
        self.assertEqual(sorted(doc["related"]["hash"]),
                         sorted(["a" * 64, "b" * 32, "c" * 40, "d" * 20]))
        self.assertEqual(doc["file"]["hash"]["sha256"], ["a" * 64])
        self.assertEqual(doc["file"]["hash"]["md5"], ["b" * 32])
        self.assertEqual(doc["file"]["hash"]["sha1"], ["c" * 40])

    def test_attachment_name_and_its_own_hash_are_sent(self):
        case = self._mail_case()
        attachment_hash = Hash.objects.create(value="E" * 64, hashtype="sha256 hash")
        attachment = File.objects.create(linked_hash=attachment_hash, file_path="files/sub/invoice.pdf",
                                         tmp_path="/tmp/x", other_names="")
        MailAttachment.objects.create(mail=case.fileOrMail.mail, file=attachment)

        doc = service.build_document(_reload(case), "case_finalised", now=NOW)

        self.assertEqual(doc["file"]["name"], ["invoice.pdf"])
        self.assertEqual(doc["file"]["hash"]["sha256"], ["e" * 64])
        self.assertEqual(doc["related"]["hash"], ["e" * 64])

    def test_uploaded_file_hash_is_sent(self):
        case = _case(self.user, results="Suspicious")
        upload = File.objects.create(linked_hash=Hash.objects.create(value="f" * 40, hashtype="SHA-1"),
                                     file_path="files/dropper.exe", tmp_path="/tmp/y", other_names="")
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, file=upload)
        case.save()

        doc = service.build_document(_reload(case), "case_finalised", now=NOW)

        self.assertEqual(doc["file"]["name"], ["dropper.exe"])
        self.assertEqual(doc["file"]["hash"]["sha1"], ["f" * 40])
        self.assertEqual(doc["related"]["hash"], ["f" * 40])

    def test_same_hash_as_ioc_and_attachment_is_not_duplicated(self):
        case = self._mail_case()
        shared = Hash.objects.create(value="a" * 64, hashtype="sha256 hash")
        attachment = File.objects.create(linked_hash=shared, file_path="files/a.bin", tmp_path="/t", other_names="")
        MailAttachment.objects.create(mail=case.fileOrMail.mail, file=attachment)
        artifact = MailArtifact.objects.create(mail=case.fileOrMail.mail, artifact_type="Hash")
        artifact.artifactIsHash = ArtifactIsHash.objects.create(artifact=artifact, hash=shared)
        artifact.save()

        doc = service.build_document(_reload(case), "case_finalised", now=NOW)

        self.assertEqual(doc["related"]["hash"], ["a" * 64])
        self.assertEqual(doc["file"]["hash"]["sha256"], ["a" * 64])

    def test_ip_in_url_host_goes_to_related_ip_not_hosts(self):
        case = _case(self.user, results="Suspicious")
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(
            case=case, url=URL.objects.create(address="http://198.51.100.9:8080/x"))
        case.save()
        doc = service.build_document(_reload(case), "case_finalised", now=NOW)
        self.assertEqual(doc["related"]["ip"], ["198.51.100.9"])
        self.assertNotIn("hosts", doc["related"])

    def test_invalid_ip_value_is_dropped(self):
        case = _case(self.user, results="Suspicious")
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, ip=IP.objects.create(address="not-an-ip"))
        case.save()
        doc = service.build_document(_reload(case), "case_finalised", now=NOW)
        self.assertNotIn("related", doc)

    def test_empty_fields_are_omitted(self):
        doc = service.build_document(_reload(_case(self.user, results="Dangerous")), "case_finalised", now=NOW)
        for key in ("email", "url", "file", "related"):
            self.assertNotIn(key, doc)
        self.assertNotIn("decisive_rule", doc["suspicious"])

    def test_values_are_capped_and_deduplicated(self):
        case = _case(self.user, results="Suspicious")
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(
            case=case, url=URL.objects.create(address="http://x.test/" + "a" * 5000))
        case.save()
        doc = service.build_document(_reload(case), "case_finalised", now=NOW)
        self.assertEqual(len(doc["url"]["original"][0]), 512)

        self.assertEqual(service._dedupe(["a", "b", "a", "", None, "b", "c"]), ["a", "b", "c"])

    def test_non_dict_verdict_explanation_is_ignored(self):
        case = _case(self.user, results="Dangerous", verdict_explanation=["oops"])
        doc = service.build_document(_reload(case), "case_finalised", now=NOW)
        self.assertNotIn("decisive_rule", doc["suspicious"])

    def test_build_update_carries_verdict_fields_only(self):
        case = _case(self.user, results="Safe", final_score=1.0, final_confidence=70)
        update = service.build_update(_reload(case), "case_modified", now=NOW)
        self.assertEqual(update["suspicious"]["verdict"], "Safe")
        self.assertEqual(update["suspicious"]["score"], 1.0)
        self.assertEqual(update["event"]["action"], "case_modified")
        self.assertEqual(update["event"]["risk_score"], 1.0)
        self.assertEqual(update["@timestamp"], NOW.isoformat())
        self.assertIsNone(update["suspicious"]["decisive_rule"])  # explicit null clears a stale rule
        for key in ("email", "url", "file", "related"):
            self.assertNotIn(key, update)


class SiemClientTests(SimpleTestCase):
    CONFIG = {"url": "https://siem.corp:9200/", "api_key": "KEY123", "index": "idx"}

    def _client(self, **overrides):
        session = mock.Mock()
        with mock.patch.object(service, "make_session", return_value=session):
            client = service.SiemClient({**self.CONFIG, **overrides})
        return client, session

    def test_missing_url_or_key_raises(self):
        for config in ({}, {"url": "https://x"}, {"api_key": "k"}, {"url": " ", "api_key": "k"}):
            with self.assertRaises(ValueError):
                service.SiemClient(config)

    def test_non_http_url_raises(self):
        with self.assertRaises(ValueError):
            service.SiemClient({"url": "ftp://x", "api_key": "k"})

    def test_put_case_request_shape(self):
        client, session = self._client()
        session.request.return_value = fake_response(201, {"result": "created"})
        client.put_case(42, {"a": 1})
        args, kwargs = session.request.call_args
        self.assertEqual(args, ("PUT", "https://siem.corp:9200/idx/_doc/42"))
        self.assertEqual(kwargs["headers"]["Authorization"], "ApiKey KEY123")
        self.assertEqual(json.loads(kwargs["data"]), {"a": 1})
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")
        self.assertEqual(kwargs["timeout"], 10)
        self.assertIs(kwargs["verify"], True)

    def test_timeout_and_verify_come_from_config(self):
        client, session = self._client(timeout_seconds=3, verify_tls=False)
        session.request.return_value = fake_response(200)
        client.put_case(1, {})
        self.assertEqual(session.request.call_args[1]["timeout"], 3)
        self.assertIs(session.request.call_args[1]["verify"], False)
        client, session = self._client(verify_tls="false")
        session.request.return_value = fake_response(200)
        client.put_case(1, {})
        self.assertIs(session.request.call_args[1]["verify"], False)

    def test_put_case_errors_raise(self):
        for status in (400, 429, 500, 503):
            client, session = self._client()
            session.request.return_value = fake_response(status, text="boom")
            with self.assertRaises(service.SiemError) as ctx:
                client.put_case(1, {})
            self.assertIn(str(status), str(ctx.exception))

    def test_auth_errors_say_so_and_never_leak_the_key(self):
        for status in (401, 403):
            client, session = self._client()
            session.request.return_value = fake_response(status, text="KEY123 rejected")
            with self.assertRaises(service.SiemError) as ctx:
                client.put_case(1, {})
            self.assertIn("authentication failed", str(ctx.exception))
            self.assertNotIn("KEY123", str(ctx.exception))

    def test_transport_errors_propagate(self):
        import requests
        for exc in (requests.Timeout("slow"), requests.ConnectionError("refused")):
            client, session = self._client()
            session.request.side_effect = exc
            with self.assertRaises(requests.RequestException):
                client.put_case(1, {})

    def test_update_case_request_shape_and_result(self):
        client, session = self._client()
        session.request.return_value = fake_response(200)
        self.assertTrue(client.update_case(42, {"suspicious": {"verdict": "Safe"}}))
        args, kwargs = session.request.call_args
        self.assertEqual(args, ("POST", "https://siem.corp:9200/idx/_update/42"))
        self.assertEqual(json.loads(kwargs["data"]), {"doc": {"suspicious": {"verdict": "Safe"}}})

    def test_update_case_404_is_success_returning_false(self):
        client, session = self._client()
        session.request.return_value = fake_response(404, text="document_missing_exception")
        self.assertFalse(client.update_case(42, {}))

    def test_update_case_other_errors_raise(self):
        client, session = self._client()
        session.request.return_value = fake_response(500)
        with self.assertRaises(service.SiemError):
            client.update_case(42, {})

    def test_ensure_index_skips_when_present(self):
        client, session = self._client()
        session.request.return_value = fake_response(200)
        client.ensure_index()
        self.assertEqual(session.request.call_count, 1)
        self.assertEqual(session.request.call_args[0], ("HEAD", "https://siem.corp:9200/idx"))

    def test_ensure_index_creates_on_404_with_mappings_only(self):
        client, session = self._client()
        session.request.side_effect = [fake_response(404), fake_response(200, {"acknowledged": True})]
        client.ensure_index()
        args, kwargs = session.request.call_args
        self.assertEqual(args, ("PUT", "https://siem.corp:9200/idx"))
        body = json.loads(kwargs["data"])
        self.assertEqual(set(body), {"mappings"})  # no shard/replica settings: serverless-safe
        props = body["mappings"]["properties"]
        self.assertEqual(props["related"]["properties"]["ip"]["type"], "ip")
        self.assertEqual(props["@timestamp"]["type"], "date")
        self.assertIs(props["suspicious"]["dynamic"], False)

    def test_mapping_types_the_mail_fields(self):
        email = service.index_body()["mappings"]["properties"]["email"]["properties"]
        self.assertEqual(email["cc"]["properties"]["address"]["type"], "keyword")
        self.assertEqual(email["message_id"]["type"], "keyword")

    def test_ensure_index_already_exists_race_is_success(self):
        client, session = self._client()
        session.request.side_effect = [
            fake_response(404),
            fake_response(400, {"error": {"type": "resource_already_exists_exception"}},
                          text='{"error":{"type":"resource_already_exists_exception"}}'),
        ]
        client.ensure_index()

    def test_ensure_index_create_failure_raises(self):
        client, session = self._client()
        session.request.side_effect = [fake_response(404), fake_response(400, text="bad mapping")]
        with self.assertRaises(service.SiemError):
            client.ensure_index()

    def test_ensure_index_disabled_makes_no_call(self):
        client, session = self._client(create_index=False)
        client.ensure_index()
        session.request.assert_not_called()

    def test_ensure_index_head_auth_error_raises(self):
        client, session = self._client()
        session.request.return_value = fake_response(403)
        with self.assertRaises(service.SiemError):
            client.ensure_index()

    def test_bulk_ndjson_and_counts(self):
        client, session = self._client()
        session.request.return_value = fake_response(200, {
            "errors": True,
            "items": [{"index": {"status": 201}}, {"index": {"status": 400, "error": {}}}],
        })
        ok, errors = client.bulk([(1, {"a": 1}), (2, {"b": 2})])
        self.assertEqual((ok, errors), (1, 1))
        args, kwargs = session.request.call_args
        self.assertEqual(args, ("POST", "https://siem.corp:9200/_bulk"))
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/x-ndjson")
        lines = kwargs["data"].decode().strip().split("\n")
        self.assertEqual(json.loads(lines[0]), {"index": {"_index": "idx", "_id": "1"}})
        self.assertEqual(json.loads(lines[1]), {"a": 1})
        self.assertEqual(len(lines), 4)

    def test_bulk_http_failure_raises(self):
        client, session = self._client()
        session.request.return_value = fake_response(500)
        with self.assertRaises(service.SiemError):
            client.bulk([(1, {})])
