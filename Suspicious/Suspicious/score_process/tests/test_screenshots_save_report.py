"""create_and_save_report wires the screenshot registry into the scoring path.

The parser resolve/run is patched (see test_get_report / test_enrichment_persist
for the real path) so execution reaches report.save + the screenshot block.
"""
from unittest.mock import MagicMock, patch

from django.test import TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from url_process.models import URL
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
SCORED = {"score": 7, "confidence": 6, "level": "suspicious", "category": "Phishing"}


def _fake_resolve(*_a, **_k):
    parser = MagicMock()
    parser.run.return_value = dict(SCORED)
    return MagicMock(return_value=parser)


class SaveReportScreenshotTest(TestCase):
    def _report(self, name="Lookyloo_Screenshot"):
        a = Analyzer.objects.create(name=name, analyzer_cortex_id=name)
        u = URL.objects.create(address="http://x.test")
        return AnalyzerReport.objects.create(
            cortex_job_id="j", type="url", status="Success", analyzer=a, url=u,
            level="info", confidence=0, score=0,
            report_summary={"taxonomies": []}, report_taxonomy={},
            report_full={"screenshot": ""},
        )

    @patch("score_process.scoring.cortex_analyzers.registry.registry.resolve",
           side_effect=_fake_resolve)
    @patch("score_process.scoring.screenshots.registry.store")
    @patch("score_process.scoring.screenshots.registry.capture", return_value=PNG)
    def test_capture_and_store_called(self, cap, store, _resolve):
        report = self._report()
        CortexAnalyzerReports.create_and_save_report(
            report, artifact_value="http://x.test", case_id=None)

        cap.assert_called_once_with(report)
        store.assert_called_once_with(report, PNG)
        report.refresh_from_db()
        self.assertEqual(report.score, 7)

    @patch("score_process.scoring.cortex_analyzers.registry.registry.resolve",
           side_effect=_fake_resolve)
    @patch("score_process.scoring.screenshots.registry.capture",
           side_effect=RuntimeError("boom"))
    def test_capture_failure_does_not_break_scoring(self, cap, _resolve):
        report = self._report()
        # must not raise; scoring fields still persisted
        CortexAnalyzerReports.create_and_save_report(
            report, artifact_value="http://x.test", case_id=None)

        cap.assert_called_once_with(report)
        report.refresh_from_db()
        self.assertEqual(report.score, 7)
        self.assertEqual(report.confidence, 6)
        self.assertEqual(report.level, "suspicious")
        self.assertEqual(report.screenshot_key, "")
