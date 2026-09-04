from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case, CaseHasNonFileIocs
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP


def _make_user(username):
    u = User.objects.create_user(username=username, password="pw-12345")
    g, _ = Group.objects.get_or_create(name="CERT")
    u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class AnalyzerEnrichmentApiTests(TestCase):
    def setUp(self):
        self.user = _make_user("u")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_mail_road_analyzer_report_carries_enrichment(self):
        case = Case.objects.create(description="d", reporter=self.user)
        ip = IP.objects.create(address="8.8.8.8")
        iocs = CaseHasNonFileIocs.objects.create(case=case, ip=ip)
        case.nonFileIocs = iocs
        case.save()
        a = Analyzer.objects.create(name="VirusTotal_GetReport_3_1", analyzer_cortex_id="vt", tier=1)
        AnalyzerReport.objects.create(
            cortex_job_id="j", type="ip", status="Success", analyzer=a, ip=ip,
            level="suspicious", confidence=60, score=7,
            report_summary={}, report_taxonomy={}, report_full={},
            enrichment={"source": "virustotal", "as_owner": "Google LLC", "vendors": []},
        )
        r = self.client.get(f"/api/investigations/{case.id}/")
        reports = r.json()["analyzer_reports"]
        self.assertEqual(reports[0]["enrichment"]["source"], "virustotal")
        self.assertEqual(reports[0]["target"], {"kind": "IP", "id": ip.id, "value": "8.8.8.8"})
