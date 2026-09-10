from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from url_process.models import URL

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


class BackfillScreenshotsTest(TestCase):
    def _report(self, name="Lookyloo_Screenshot", cortex_id="lookyloo-1", job="j"):
        a = Analyzer.objects.create(name=f"{name}-{cortex_id}", analyzer_cortex_id=cortex_id)
        u = URL.objects.create(address="http://x.test")
        return AnalyzerReport.objects.create(
            cortex_job_id=job, type="url", status="Success", analyzer=a, url=u,
            level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={"screenshot": ""},
        )

    @patch("score_process.scoring.screenshots.registry.store")
    @patch("score_process.scoring.screenshots.registry.capture", return_value=PNG)
    def test_dry_run_writes_nothing(self, cap, store):
        self._report()
        call_command("backfill_screenshots", "--dry-run", stdout=StringIO())
        store.assert_not_called()

    @patch("score_process.scoring.screenshots.registry.store")
    @patch("score_process.scoring.screenshots.registry.capture", return_value=PNG)
    def test_stores_for_missing(self, cap, store):
        r = self._report()
        call_command("backfill_screenshots", stdout=StringIO())
        store.assert_called_once_with(r, PNG)

    @patch("score_process.scoring.screenshots.registry.store")
    @patch("score_process.scoring.screenshots.registry.capture", return_value=PNG)
    def test_skips_non_screenshot_analyzers(self, cap, store):
        self._report(name="VirusTotal_GetReport_3_1", cortex_id="vt-1")
        call_command("backfill_screenshots", stdout=StringIO())
        cap.assert_not_called()
        store.assert_not_called()

    @patch("score_process.scoring.screenshots.registry.store")
    @patch("score_process.scoring.screenshots.registry.capture", return_value=PNG)
    def test_skips_already_captured(self, cap, store):
        r = self._report()
        r.screenshot_key = "report-1.png"
        r.save(update_fields=["screenshot_key"])
        call_command("backfill_screenshots", stdout=StringIO())
        cap.assert_not_called()

    @patch("score_process.scoring.screenshots.registry.store")
    @patch("score_process.scoring.screenshots.registry.capture", return_value=None)
    def test_skips_when_no_png(self, cap, store):
        self._report()
        call_command("backfill_screenshots", stdout=StringIO())  # no error
        store.assert_not_called()

    @patch("score_process.scoring.screenshots.registry.store")
    @patch("score_process.scoring.screenshots.registry.capture", return_value=PNG)
    def test_limit_caps_scan(self, cap, store):
        self._report(cortex_id="lookyloo-1", job="j1")
        self._report(cortex_id="lookyloo-2", job="j2")
        call_command("backfill_screenshots", "--limit", "1", stdout=StringIO())
        self.assertEqual(store.call_count, 1)
