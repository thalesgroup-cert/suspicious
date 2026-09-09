from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from url_process.models import URL


def _make_user(username, *, investigator):
    u = User.objects.create_user(username=username, password="pw-12345")
    if investigator:
        g, _ = Group.objects.get_or_create(name="CERT")
        u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class SubmissionTicketTests(TestCase):
    def setUp(self):
        self.user = _make_user("soc", investigator=True)
        self.client = APIClient()
        self.client.force_authenticate(self.user)

        group = ObservableGroup.objects.create()
        self.ip = IP.objects.create(address="8.8.8.8", ioc_level="malicious",
                                    ioc_score=9, ioc_confidence=0.8)
        self.url = URL.objects.create(address="https://evil.example/login")
        ObservableGroupArtifact.objects.create(group=group, artifact_type="IP", ip=self.ip)
        ObservableGroupArtifact.objects.create(group=group, artifact_type="URL", url=self.url)
        self.case = Case.objects.create(
            description="d", reporter=self.user, observable_group=group,
            results="Dangerous", final_score=92.0, final_confidence=0.8,
            category_ai="Phishing",
            verdict_rationale=["VirusTotal flagged 8.8.8.8 as malicious."],
        )
        a = Analyzer.objects.create(name="VirusTotal_GetReport_3_1",
                                    analyzer_cortex_id="vt", tier=1)
        AnalyzerReport.objects.create(
            cortex_job_id="j1", type="ip", status="Success", analyzer=a, ip=self.ip,
            level="malicious", confidence=90, score=10,
            report_summary={}, report_taxonomy={}, report_full={},
        )

    def _url(self):
        return f"/api/submissions/{self.case.id}/ticket/"

    def test_ticket_payload_shape(self):
        r = self.client.get(self._url())
        self.assertEqual(r.status_code, 200)
        body = r.json()

        self.assertEqual(body["case_id"], self.case.id)
        self.assertEqual(body["verdict"]["result"], "Dangerous")
        self.assertEqual(body["verdict"]["severity"], 4)
        self.assertEqual(body["verdict"]["ai_classification"], "Phishing")
        self.assertIn("VirusTotal flagged", body["verdict"]["rationale"][0])
        self.assertTrue(body["recommended_action"])

        obs = {o["data"]: o for o in body["observables"]}
        self.assertEqual(obs["8.8.8.8"]["dataType"], "ip")
        self.assertEqual(obs["8.8.8.8"]["verdict"], "malicious")
        self.assertEqual(obs["https://evil.example/login"]["verdict"], "inconclusive")

        summary = body["analyzer_summary"]
        self.assertEqual(summary["total_reports"], 1)
        self.assertEqual(summary["by_verdict"].get("malicious"), 1)
        self.assertIn("VirusTotal_GetReport_3_1", summary["analyzers"])

    def test_requires_investigator(self):
        self.client.force_authenticate(_make_user("reporter", investigator=False))
        self.assertEqual(self.client.get(self._url()).status_code, 403)

    def test_requires_auth(self):
        self.client.force_authenticate(None)
        self.assertIn(self.client.get(self._url()).status_code, (401, 403))

    def test_unknown_case_404(self):
        self.assertEqual(self.client.get("/api/submissions/999999/ticket/").status_code, 404)
