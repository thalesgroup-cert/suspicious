import json
from pathlib import Path

from django.test import TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

FIX = Path(__file__).parent / "fixtures" / "virustotal"


class EnrichmentPersistTests(TestCase):
    def test_vt_report_gets_enrichment_on_score(self):
        full = json.loads((FIX / "ip_lone_fp.json").read_text())["report_full"]
        ip = IP.objects.create(address="8.8.8.8")
        a = Analyzer.objects.create(name="VirusTotal_GetReport_3_1", analyzer_cortex_id="VirusTotal_GetReport_3_1", tier=1)
        r = AnalyzerReport.objects.create(
            cortex_job_id="j", type="ip", status="Success", analyzer=a, ip=ip,
            level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full=full,
        )
        CortexAnalyzerReports.create_and_save_report(r, "8.8.8.8", None)
        r.refresh_from_db()
        self.assertIsNotNone(r.enrichment)
        self.assertEqual(r.enrichment["source"], "virustotal")
        self.assertEqual(r.enrichment["as_owner"], "Google LLC")

    def test_non_vt_report_enrichment_stays_none(self):
        a = Analyzer.objects.create(name="FileInfo_8_0", analyzer_cortex_id="FileInfo_8_0")
        ip = IP.objects.create(address="1.1.1.1")
        r = AnalyzerReport.objects.create(
            cortex_job_id="j2", type="ip", status="Success", analyzer=a, ip=ip,
            level="info", confidence=0, score=0,
            report_summary={"taxonomies": []}, report_taxonomy={}, report_full={},
        )
        CortexAnalyzerReports.create_and_save_report(r, "1.1.1.1", None)
        r.refresh_from_db()
        self.assertIsNone(r.enrichment)
