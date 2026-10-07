from unittest import mock

from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case


@override_settings(ROOT_URLCONF="suspicious.urls")
class InvestigationSearchEsTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("cert", "c@x.io", "pw-12345")
        cls.user.groups.add(Group.objects.get_or_create(name="CERT")[0])
        cls.a = Case.objects.create(description="alpha only", reporter=cls.user)
        cls.b = Case.objects.create(description="beta only", reporter=cls.user)

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def _ids(self, q):
        r = self.client.get("/api/investigations/", {"search": q})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        rows = body["results"] if isinstance(body, dict) and "results" in body else body
        return sorted(row["id"] for row in rows)

    def _patch(self, ret):
        return mock.patch("api.views.investigations.search_case_ids", return_value=ret)

    def test_es_ids_restrict_the_list(self):
        with self._patch([self.b.pk]):
            self.assertEqual(self._ids("whatever"), [self.b.pk])

    def test_empty_es_result_gives_empty_page(self):
        with self._patch([]):
            self.assertEqual(self._ids("nomatch"), [])

    def test_none_falls_back_to_orm_search(self):
        with self._patch(None):
            self.assertEqual(self._ids("alpha"), [self.a.pk])

    def test_numeric_search_still_matches_case_id(self):
        # ES returns nothing, but a digits-only search of >= 3 chars must still find the pk.
        case = Case.objects.create(id=424242, description="gamma", reporter=self.user)
        with self._patch([]):
            self.assertEqual(self._ids("424242"), [case.pk])
