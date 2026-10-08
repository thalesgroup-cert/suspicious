from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from url_process.models import URL


def _user(name, *, cert=False):
    u = User.objects.create_user(username=name, password="pw-12345")
    if cert:
        u.groups.add(Group.objects.get_or_create(name="CERT")[0])
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class MarkdownReportTests(TestCase):
    def setUp(self):
        self.user = _user("analyst", cert=True)
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        group = ObservableGroup.objects.create()
        self.ip = IP.objects.create(address="203.0.113.7")
        self.url = URL.objects.create(address="http://evil.test/a|b")
        ObservableGroupArtifact.objects.create(group=group, artifact_type="IP", ip=self.ip)
        ObservableGroupArtifact.objects.create(group=group, artifact_type="URL", url=self.url)
        self.case = Case.objects.create(
            description="Reported by SOC", reporter=self.user, observable_group=group,
            results="Dangerous", final_score=9.0, final_confidence=82.0,
            verdict_explanation={
                "band": "dangerous", "confidence": 0.82, "decisive_rule": "tier-1 malicious",
                "analyst_paragraph": "The address is a known C2 host.",
                "reporter_paragraph": "This indicator is dangerous.",
                "confidence_reading": "High confidence: 2 of 3 sources agree.",
                "sources": [{"name": "VirusTotal", "tier": 1, "verdict": "malicious", "counted": True, "note": "12/70"}],
            },
        )
        vt = Analyzer.objects.create(name="VirusTotal", analyzer_cortex_id="vt", tier=1)
        AnalyzerReport.objects.create(
            cortex_job_id="j1", type="ip", status="Success", analyzer=vt, ip=self.ip,
            level="malicious", confidence=90, score=10, report_summary={}, report_taxonomy={},
            report_full={}, category="[x](javascript:alert(1)) | pipe",
            enrichment={"threat_category": "trojan", "threat_label": "trojan.x"},
        )
        sh = Analyzer.objects.create(name="Shodan", analyzer_cortex_id="sh", tier=2)
        AnalyzerReport.objects.create(
            cortex_job_id="j2", type="ip", status="Failure", analyzer=sh, ip=self.ip,
            level="info", confidence=1, score=1, report_summary={}, report_taxonomy={}, report_full={},
        )

    def _get(self, case_id=None):
        return self.client.get(f"/api/cases/{case_id or self.case.id}/report.md")

    def test_returns_a_markdown_attachment(self):
        r = self._get()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r["Content-Type"].startswith("text/markdown"))
        self.assertIn(f'filename="case-{self.case.id}-report.md"', r["Content-Disposition"])

    def test_contains_the_verdict_explanation_and_indicators(self):
        body = self._get().content.decode()
        self.assertIn(f"# Case #{self.case.id}", body)
        self.assertIn("Dangerous", body)
        self.assertIn("The address is a known C2 host.", body)
        self.assertIn("High confidence: 2 of 3 sources agree.", body)
        self.assertIn("`203.0.113.7`", body)
        self.assertIn("VirusTotal", body)

    def test_threat_classification_and_failed_analyzers_are_listed(self):
        body = self._get().content.decode()
        self.assertIn("trojan.x", body)
        self.assertIn("Shodan", body)
        self.assertRegex(body, r"(?i)analyzers? failed")

    def test_untrusted_text_cannot_make_links_or_break_tables(self):
        body = self._get().content.decode()
        self.assertNotIn("[x](javascript", body)           # no live link from analyzer evidence
        for line in body.splitlines():
            if line.startswith("|") and "VirusTotal" in line:
                self.assertEqual(line.count("|") - line.count("\\|"), 5, line)  # 4 columns: no stray pipes
        self.assertIn("evil.test", body)

    def test_snake_case_names_stay_readable(self):
        Analyzer.objects.filter(name="VirusTotal").update(name="Abuse_Finder_3_0")
        self.assertIn("Abuse_Finder_3_0", self._get().content.decode())

    def test_block_markers_in_reporter_text_are_neutralised(self):
        self.case.description = "# Fake heading\n- injected bullet"
        self.case.save(update_fields=["description"])
        body = self._get().content.decode()
        lines = body.splitlines()
        self.assertNotIn("# Fake heading", lines)               # not a heading of its own
        self.assertTrue(any(line.startswith("\\# Fake heading") for line in lines))

    def test_a_case_without_indicators_says_so(self):
        owner = _user("reporter")
        plain = Case.objects.create(description="mail", reporter=owner, results="Safe")
        self.client.force_authenticate(owner)
        body = self._get(plain.id).content.decode()
        self.assertIn("No indicator observables", body)

    def test_other_users_cannot_read_the_report(self):
        self.client.force_authenticate(_user("stranger"))
        self.assertEqual(self._get().status_code, 403)
