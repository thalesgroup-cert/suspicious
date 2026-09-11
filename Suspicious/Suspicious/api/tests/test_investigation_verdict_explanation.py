from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from ip_process.models import IP

_EXPLANATION = {
    "band": "Dangerous",
    "decisive_rule": "tier1-authoritative-malicious",
    "analyst_paragraph": "A.",
    "reporter_paragraph": "R.",
    "confidence_reading": "C.",
    "confidence": 90,
    "sources": [],
}


def _make_user(username):
    u = User.objects.create_user(username=username, password="pw-12345")
    g, _ = Group.objects.get_or_create(name="CERT")
    u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class InvestigationVerdictExplanationTests(TestCase):
    def setUp(self):
        self.user = _make_user("u")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

        g = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(
            group=g, artifact_type="IP", ip=IP.objects.create(address="8.8.8.8")
        )
        self.case = Case.objects.create(
            description="d", reporter=self.user, observable_group=g, results="Dangerous"
        )
        self.case.verdict_explanation = _EXPLANATION
        self.case.save()

        og = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(
            group=og, artifact_type="IP", ip=IP.objects.create(address="1.1.1.1")
        )
        self.plain_case = Case.objects.create(
            description="d2", reporter=self.user, observable_group=og
        )

    def test_detail_exposes_verdict_explanation(self):
        resp = self.client.get(reverse("investigation-details", args=[self.case.id]))
        self.assertEqual(
            resp.data["case_infos"]["verdict_explanation"]["decisive_rule"],
            "tier1-authoritative-malicious",
        )

    def test_detail_verdict_explanation_null_when_unset(self):
        resp = self.client.get(
            reverse("investigation-details", args=[self.plain_case.id])
        )
        self.assertIsNone(resp.data["case_infos"]["verdict_explanation"])

    def test_list_rows_have_no_case_infos(self):
        resp = self.client.get(reverse("investigation-list"))
        rows = resp.data["results"]
        self.assertTrue(rows)
        for row in rows:
            self.assertNotIn("case_infos", row)
            self.assertNotIn("verdict_explanation", row)
