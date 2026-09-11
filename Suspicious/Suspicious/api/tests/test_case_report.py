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
class CaseReportTests(TestCase):
    def setUp(self):
        self.user = _make_user("u")
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        g = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(
            group=g, artifact_type="IP", ip=IP.objects.create(address="8.8.8.8")
        )
        self.case = Case.objects.create(
            description="d", reporter=self.user, observable_group=g, results="Safe"
        )

    def test_html_report(self):
        r = self.client.get(f"/api/cases/{self.case.id}/report/?format=html")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/html", r["Content-Type"])
        self.assertIn("8.8.8.8", r.content.decode())
        self.assertIn("Safe", r.content.decode())

    def test_requires_auth(self):
        self.client.force_authenticate(None)
        self.assertIn(
            self.client.get(f"/api/cases/{self.case.id}/report/").status_code, (401, 403)
        )

    def test_report_renders_enrichment(self):
        from cortex_job.models import Analyzer, AnalyzerReport
        a = Analyzer.objects.create(name="VirusTotal_GetReport_3_1", analyzer_cortex_id="vt", tier=1)
        ip = self.case.observable_group.artifacts.first().ip
        AnalyzerReport.objects.create(
            cortex_job_id="j", type="ip", status="Success", analyzer=a, ip=ip,
            level="malicious", confidence=90, score=10,
            report_summary={}, report_taxonomy={}, report_full={},
            enrichment={"source": "virustotal", "malicious_count": 42, "total": 70,
                        "as_owner": "Evil Hosting LLC", "threat_label": "trojan.emotet",
                        "vendors": [{"name": "Kaspersky", "category": "malicious", "result": "Trojan"}]},
        )
        r = self.client.get(f"/api/cases/{self.case.id}/report/?format=html")
        body = r.content.decode()
        self.assertIn("Evil Hosting LLC", body)
        self.assertIn("42 / 70", body)
        self.assertIn("trojan.emotet", body)
