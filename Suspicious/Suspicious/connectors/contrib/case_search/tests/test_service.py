import sys
import types
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasNonFileIocs
from connectors.contrib.case_search import service
from mail_feeder.models import Mail
from case_handler.models import CaseHasFileOrMail
from url_process.models import URL


def _case(user, **kw):
    return Case.objects.create(description=kw.pop("description", "d"), reporter=user, **kw)


class BuildDocumentTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", "alice@x.io", "pw")

    def test_url_ioc_and_reporter_and_description(self):
        case = _case(self.user, description="invoice phish")
        url = URL.objects.create(address="http://evil.test/login")
        assoc = CaseHasNonFileIocs.objects.create(case=case, url=url)
        case.nonFileIocs = assoc
        case.save()
        case = Case.objects.select_related(*service.CASE_RELATED).get(pk=case.pk)

        doc = service.build_document(case)

        self.assertEqual(doc["description"], "invoice phish")
        self.assertIn("alice@x.io", doc["reporter"])
        self.assertIn("alice", doc["reporter"])
        self.assertEqual(doc["observables"], ["http://evil.test/login"])
        self.assertEqual(doc["mail_subject"], "")

    def test_mail_subject(self):
        case = _case(self.user)
        mail = Mail.objects.create(
            subject="Your invoice", reportedBy="r", date=timezone.now(), to="t", mail_id="m1",
        )
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save()
        case = Case.objects.select_related(*service.CASE_RELATED).get(pk=case.pk)

        self.assertEqual(service.build_document(case)["mail_subject"], "Your invoice")

    def test_long_values_are_truncated(self):
        case = _case(self.user)
        url = URL.objects.create(address="http://x.test/" + "a" * 5000)
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, url=url)
        case.save()
        case = Case.objects.select_related(*service.CASE_RELATED).get(pk=case.pk)

        self.assertEqual(len(service.build_document(case)["observables"][0]), 512)


class SearchCaseIdsTests(TestCase):
    def _enabled(self, enabled=True):
        return mock.patch(
            "connectors.delivery.get_state", return_value=mock.Mock(enabled=enabled)
        )

    def test_out_of_range_queries_skip_es(self):
        with mock.patch.object(service, "get_client") as gc:
            self.assertIsNone(service.search_case_ids("ab"))
            self.assertIsNone(service.search_case_ids("x" * 21))
            self.assertIsNone(service.search_case_ids(None))
            gc.assert_not_called()

    def test_disabled_connector_returns_none(self):
        with self._enabled(False), mock.patch.object(service, "get_client") as gc:
            self.assertIsNone(service.search_case_ids("evil.test"))
            gc.assert_not_called()

    def test_returns_ids_from_hits(self):
        client = mock.Mock()
        client.search.return_value = {"hits": {"hits": [{"_id": "7"}, {"_id": "3"}]}}
        with self._enabled(), mock.patch.object(service, "get_client", return_value=client):
            self.assertEqual(service.search_case_ids("evil.test"), [7, 3])

    def test_no_hits_returns_empty_list_not_none(self):
        client = mock.Mock()
        client.search.return_value = {"hits": {"hits": []}}
        with self._enabled(), mock.patch.object(service, "get_client", return_value=client):
            self.assertEqual(service.search_case_ids("evil.test"), [])

    def test_wildcard_characters_are_sent_as_a_plain_match(self):
        client = mock.Mock()
        client.search.return_value = {"hits": {"hits": []}}
        with self._enabled(), mock.patch.object(service, "get_client", return_value=client):
            service.search_case_ids('a*b"(c')
        query = client.search.call_args.kwargs["query"]
        self.assertEqual(query["multi_match"]["query"], 'a*b"(c')

    def test_any_error_falls_back_to_none(self):
        client = mock.Mock()
        client.search.side_effect = RuntimeError("index_not_found")
        with self._enabled(), mock.patch.object(service, "get_client", return_value=client):
            self.assertIsNone(service.search_case_ids("evil.test"))


class FakeBadRequest(Exception):
    def __init__(self, error):
        super().__init__(error)
        self.error = error


class EnsureIndexTests(TestCase):
    def _ensure(self, error):
        client = mock.Mock()
        client.indices.exists.return_value = False
        client.indices.create.side_effect = FakeBadRequest(error)
        stub = types.SimpleNamespace(BadRequestError=FakeBadRequest)
        with mock.patch.dict(sys.modules, {"elasticsearch": stub}):
            service.ensure_index(client, "idx")

    def test_already_exists_is_swallowed(self):
        self._ensure("resource_already_exists_exception")

    def test_other_bad_request_is_raised(self):
        with self.assertRaises(FakeBadRequest):
            self._ensure("illegal_argument_exception")


class DescriptionTruncationTests(TestCase):
    def test_long_description_is_truncated(self):
        user = User.objects.create_user("trunc", "t@x.io", "pw")
        case = Case.objects.create(description="x" * 10_000, reporter=user)
        self.assertEqual(len(service.build_document(case)["description"]), 4096)


class GetClientTests(TestCase):
    def test_client_has_no_retries_and_uses_timeout(self):
        stub = types.ModuleType("elasticsearch")
        stub.Elasticsearch = mock.Mock()
        with mock.patch.dict(sys.modules, {"elasticsearch": stub}):
            service.get_client({"url": "http://es:9200"}, timeout=2.0)
        stub.Elasticsearch.assert_called_once_with(
            "http://es:9200", request_timeout=2.0, max_retries=0,
        )
