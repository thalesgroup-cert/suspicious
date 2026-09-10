import json
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.test import TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP

FIX = Path(__file__).parent / "fixtures" / "virustotal"


class BackfillEnrichmentTests(TestCase):
    def _vt_report(self, **kw):
        full = json.loads((FIX / "ip_lone_fp.json").read_text())["report_full"]
        a, _ = Analyzer.objects.get_or_create(name="VirusTotal_GetReport_3_1", defaults={"analyzer_cortex_id": "vt"})
        ip = IP.objects.create(address=kw.get("addr", "8.8.8.8"))
        return AnalyzerReport.objects.create(
            cortex_job_id=kw.get("job", "j"), type="ip", status="Success", analyzer=a, ip=ip,
            level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full=full,
        )

    def test_backfills_null_enrichment(self):
        r = self._vt_report()
        self.assertIsNone(r.enrichment)
        call_command("backfill_enrichment", stdout=StringIO())
        r.refresh_from_db()
        self.assertEqual(r.enrichment["source"], "virustotal")

    def test_dry_run_writes_nothing(self):
        r = self._vt_report(addr="9.9.9.9", job="j2")
        call_command("backfill_enrichment", "--dry-run", stdout=StringIO())
        r.refresh_from_db()
        self.assertIsNone(r.enrichment)

    def test_skips_already_enriched(self):
        r = self._vt_report(addr="1.2.3.4", job="j3")
        r.enrichment = {"source": "manual"}
        r.save(update_fields=["enrichment"])
        call_command("backfill_enrichment", stdout=StringIO())
        r.refresh_from_db()
        self.assertEqual(r.enrichment["source"], "manual")

    def test_dry_run_stdout_reports_correct_count(self):
        self._vt_report(addr="2.2.2.2", job="j4")
        out = StringIO()
        call_command("backfill_enrichment", "--dry-run", stdout=out)
        self.assertIn("would write 1", out.getvalue())
