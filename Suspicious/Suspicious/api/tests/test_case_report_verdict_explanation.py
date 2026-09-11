from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from ip_process.models import IP


def _make_user(username):
    u = User.objects.create_user(username=username, password="pw-12345")
    g, _ = Group.objects.get_or_create(name="CERT")
    u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class CaseReportVerdictExplanationTests(TestCase):
    def setUp(self):
        self.user = _make_user("u")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def _case(self):
        g = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(
            group=g, artifact_type="IP", ip=IP.objects.create(address="8.8.8.8")
        )
        return Case.objects.create(
            description="d", reporter=self.user, observable_group=g, results="Dangerous"
        )

    def test_report_renders_why_this_verdict(self):
        case = self._case()
        case.verdict_explanation = {
            "band": "Dangerous",
            "decisive_rule": "tier1-authoritative-malicious",
            "analyst_paragraph": "GTI flagged this as command-and-control.",
            "reporter_paragraph": "R.",
            "confidence_reading": "High confidence.",
            "confidence": 90,
            "sources": [
                {"name": "GTI", "tier": 1, "verdict": "malicious",
                 "counted": True, "note": "authoritative"},
            ],
        }
        case.save()

        body = self.client.get(
            f"/api/cases/{case.id}/report/?format=html"
        ).content.decode()
        self.assertIn("GTI flagged this as command-and-control.", body)
        self.assertIn("GTI", body)
        self.assertIn("Why this verdict", body)

    def test_report_falls_back_to_verdict_rationale(self):
        case = self._case()
        case.verdict_rationale = ["Two tier-2 sources disagree."]
        case.save()

        body = self.client.get(
            f"/api/cases/{case.id}/report/?format=html"
        ).content.decode()
        self.assertIn("<li>Two tier-2 sources disagree.</li>", body)
        self.assertNotIn("Why this verdict", body)
