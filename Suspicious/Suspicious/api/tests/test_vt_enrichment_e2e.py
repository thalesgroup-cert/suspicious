import json
from pathlib import Path

from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact, Result
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from score_process.scoring.apply import finalise_ioc_group
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

# __file__ = Suspicious/Suspicious/api/tests/test_vt_enrichment_e2e.py
# .parents[2] = Suspicious/Suspicious/
FIX = Path(__file__).parents[2] / "score_process" / "tests" / "fixtures" / "virustotal"


def _make_user(username):
    u = User.objects.create_user(username=username, password="pw-12345")
    g, _ = Group.objects.get_or_create(name="CERT")
    u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class VtEnrichmentE2ETests(TestCase):
    def test_lone_fp_ip_bands_not_dangerous_and_exposes_enrichment(self):
        user = _make_user("u")
        client = APIClient()
        client.force_authenticate(user)

        full = json.loads((FIX / "ip_lone_fp.json").read_text())["report_full"]
        g = ObservableGroup.objects.create()
        ip = IP.objects.create(address="8.8.8.8")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        case = Case.objects.create(description="d", reporter=user, observable_group=g)
        a = Analyzer.objects.create(
            name="VirusTotal_GetReport_3_1",
            analyzer_cortex_id="VirusTotal_GetReport_3_1", tier=1,
        )
        AnalyzerReport.objects.create(
            cortex_job_id="j", type="ip", status="Success", analyzer=a, ip=ip,
            level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full=full,
        )
        # score the report the way the pipeline does
        CortexAnalyzerReports.create_and_save_report(
            AnalyzerReport.objects.get(cortex_job_id="j"), "8.8.8.8", case.id,
        )
        finalise_ioc_group(case)

        case.refresh_from_db()
        # lone 1/N VT detection, no threat class -> refined verdict "suspicious",
        # so the group must NOT band Dangerous
        self.assertNotEqual(case.results, Result.DANGEROUS)

        body = client.get(f"/api/investigations/{case.id}/").json()
        src = body["observable_group"]["observables"][0]["sources"][0]
        self.assertEqual(src["enrichment"]["source"], "virustotal")
        self.assertEqual(src["enrichment"]["as_owner"], "Google LLC")
