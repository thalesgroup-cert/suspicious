from unittest.mock import patch, MagicMock
from uuid import uuid4

from django.test import TestCase
from cortex_job.models import Analyzer, AnalyzerReport
from cortex_job.models import URL
from score_process.scoring.screenshots import registry

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def _report(analyzer_name):
    a = Analyzer.objects.create(name=analyzer_name, analyzer_cortex_id=uuid4().hex)
    u = URL.objects.create(address="http://x.test")
    return AnalyzerReport.objects.create(
        cortex_job_id="j", type="url", status="Success", analyzer=a, url=u,
        level="info", confidence=0, score=0,
        report_summary={}, report_taxonomy={}, report_full={"screenshot": ""},
    )


class CaptureDispatchTest(TestCase):
    @patch("score_process.scoring.screenshots.registry.lookyloo.extract", return_value=PNG)
    def test_dispatches_lookyloo(self, ex):
        self.assertEqual(registry.capture(_report("Lookyloo_Screenshot")), PNG)
        ex.assert_called_once()

    @patch("score_process.scoring.screenshots.registry.urlscan.extract", return_value=PNG)
    def test_dispatches_urlscan(self, ex):
        self.assertEqual(registry.capture(_report("Urlscan.io_Scan")), PNG)

    def test_unknown_analyzer_returns_none(self):
        self.assertIsNone(registry.capture(_report("VirusTotal_GetReport_3_1")))

    @patch("score_process.scoring.screenshots.registry.lookyloo.extract", side_effect=ValueError("boom"))
    def test_extractor_raising_returns_none(self, ex):
        self.assertIsNone(registry.capture(_report("Lookyloo_Screenshot")))


class StoreTest(TestCase):
    @patch("score_process.scoring.screenshots.registry.ensure_bucket")
    @patch("score_process.scoring.screenshots.registry.get_s3_client")
    def test_store_puts_and_stamps(self, get_client, ensure):
        client = MagicMock()
        get_client.return_value = client
        r = _report("Lookyloo_Screenshot")
        registry.store(r, PNG)
        ensure.assert_called_once()
        args, kwargs = client.put_object.call_args
        self.assertEqual(args[0], "analyzer-screenshots")
        self.assertEqual(args[1], f"report-{r.id}.png")
        r.refresh_from_db()
        self.assertEqual(r.screenshot_bucket, "analyzer-screenshots")
        self.assertEqual(r.screenshot_key, f"report-{r.id}.png")
