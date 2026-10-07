import os
import uuid
from unittest import skipUnless

from django.contrib.auth.models import User
from django.test import TestCase

from case_handler.models import Case, CaseHasNonFileIocs
from connectors.contrib.case_search import service
from url_process.models import URL

ES_URL = os.environ.get("ES_TEST_URL")


@skipUnless(ES_URL, "set ES_TEST_URL to run against a real Elasticsearch")
class LiveEsTests(TestCase):
    def test_substring_search_roundtrip(self):
        config = {"url": ES_URL}
        client = service.get_client(config, timeout=10)
        index = f"suspicious-cases-test-{uuid.uuid4().hex[:8]}"
        try:
            service.ensure_index(client, index)
            user = User.objects.create_user("alice", "alice@x.io", "pw")
            case = Case.objects.create(description="d", reporter=user)
            url = URL.objects.create(address="http://phish-login.evil.test/a")
            case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, url=url)
            case.save()
            case = Case.objects.select_related(*service.CASE_RELATED).get(pk=case.pk)
            service.index_case(client, index, case)
            client.indices.refresh(index=index)

            self.assertEqual(service.search_ids(client, index, "EVIL.te"), [case.pk])
            self.assertEqual(service.search_ids(client, index, "login.evil"), [case.pk])
            self.assertEqual(service.search_ids(client, index, "zzzzz"), [])
        finally:
            client.indices.delete(index=index, ignore_unavailable=True)
