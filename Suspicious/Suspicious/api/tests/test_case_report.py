from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from ai_model.models import AiAssessment
from connectors.models import ConnectorState
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from mail_feeder.models import ArtifactIsUrl, Mail, MailArtifact
from case_handler.models import CaseHasFileOrMail
from django.utils import timezone
from url_process.models import URL


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
        self.assertIn("42/70 detections", body)
        self.assertIn("trojan.emotet", body)
        self.assertNotIn("Raw report", body)


@override_settings(ROOT_URLCONF="suspicious.urls")
class MailCaseReportTests(TestCase):
    def setUp(self):
        self.reporter = User.objects.create_user(username="rep", password="pw-12345")
        self.analyst = _make_user("cert")
        mail = Mail.objects.create(subject="s", reportedBy="r@x.test", date=timezone.now(),
                                   to="a@x.test", mail_id="m1")
        self.case = Case.objects.create(
            description="d", reporter=self.reporter, results="Dangerous",
            verdict_explanation={"band": "dangerous", "decisive_rule": "tier-1 malicious"},
        )
        self.case.fileOrMail = CaseHasFileOrMail.objects.create(case=self.case, mail=mail)
        self.case.save()
        url = URL.objects.create(address="https://evil.test/x")
        ma = MailArtifact.objects.create(mail=mail, artifact_type="URL")
        ma.artifactIsUrl = ArtifactIsUrl.objects.create(artifact=ma, url=url)
        ma.save(update_fields=["artifactIsUrl"])
        vt = Analyzer.objects.create(name="VirusTotal_GetReport_3_1", analyzer_cortex_id="vt", tier=1)
        AnalyzerReport.objects.create(
            cortex_job_id="j", type="url", status="Success", analyzer=vt, url=url,
            level="malicious", confidence=90, score=10,
            report_summary={}, report_taxonomy={}, report_full={},
        )

    def get(self, user, suffix):
        c = APIClient()
        c.force_authenticate(user)
        return c.get(f"/api/cases/{self.case.id}/report{suffix}").content.decode()

    def test_mail_case_report_lists_embedded_indicators(self):
        for body in (self.get(self.analyst, "/?format=html"), self.get(self.analyst, ".md")):
            self.assertIn("evil.test/x", body)
            self.assertIn("Dangerous", body)
            self.assertNotIn("No indicator observables", body)

    def test_reporter_download_has_no_cross_check(self):
        ConnectorState.objects.update_or_create(name="ai_model", defaults={"enabled": True})
        AiAssessment.objects.create(case=self.case, model_version="v3", result="UNWANTED", sub_class="spam",
                                    score=6, confidence=80, tier="high",
                                    probabilities={"UNWANTED": 0.8, "SAFE": 0.2})
        mine = self.get(self.reporter, ".md")
        self.assertIn("AI model assessment", mine)
        self.assertNotIn("Decisive rule", mine)
        theirs = self.get(self.analyst, ".md")
        self.assertIn("AI model assessment", theirs)
        self.assertIn("Decisive rule", theirs)
