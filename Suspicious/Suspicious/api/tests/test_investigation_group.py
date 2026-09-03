from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP


def _make_user(username):
    u = User.objects.create_user(username=username, password="pw-12345")
    g, _ = Group.objects.get_or_create(name="CERT")
    u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class InvestigationGroupApiTests(TestCase):
    def setUp(self):
        self.user = _make_user("u")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_group_case_exposes_observables_and_report(self):
        g = ObservableGroup.objects.create()
        ip = IP.objects.create(address="8.8.8.8")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        case = Case.objects.create(description="d", reporter=self.user, observable_group=g)
        a = Analyzer.objects.create(name="GTI", analyzer_cortex_id="g1", tier=1)
        AnalyzerReport.objects.create(
            cortex_job_id="j", type="ip", status="Success", analyzer=a,
            ip=ip, level="safe", confidence=95, score=0,
            report_summary={"as_owner": "Google LLC"}, report_taxonomy={}, report_full={},
        )

        r = self.client.get(f"/api/investigations/{case.id}/")
        body = r.json()
        obs = body["observable_group"]["observables"]
        self.assertEqual(obs[0]["value"], "8.8.8.8")
        self.assertEqual(obs[0]["sources"][0]["report"]["as_owner"], "Google LLC")

    def test_group_case_type_and_info(self):
        g = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(
            group=g, artifact_type="IP", ip=IP.objects.create(address="8.8.8.8")
        )
        case = Case.objects.create(description="d", reporter=self.user, observable_group=g)

        r = self.client.get(f"/api/investigations/{case.id}/")
        body = r.json()
        self.assertEqual(body["type"], "IOC")
        self.assertIn("8.8.8.8", body["info"])

    def test_group_case_findable_by_indicator(self):
        g = ObservableGroup.objects.create()
        for addr in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
            ObservableGroupArtifact.objects.create(
                group=g, artifact_type="IP", ip=IP.objects.create(address=addr)
            )
        case = Case.objects.create(description="d", reporter=self.user, observable_group=g)

        r = self.client.get("/api/investigations/?search=1.1.1.1")
        rows = [row for row in r.json()["results"] if row["id"] == case.id]
        # exactly one row despite the 3-artifact reverse-FK fan-out (.distinct())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["type"], "IOC")

    def test_mail_case_has_no_observable_group_key(self):
        case = Case.objects.create(description="d", reporter=self.user)
        r = self.client.get(f"/api/investigations/{case.id}/")
        self.assertNotIn("observable_group", r.json())
