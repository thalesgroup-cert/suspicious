from django.test import TestCase
from cortex_job.models import Analyzer, AnalyzerReport


class ScreenshotFieldsTest(TestCase):
    def test_fields_default_blank(self):
        a = Analyzer.objects.create(name="Lookyloo_Screenshot", analyzer_cortex_id="lookyloo_screenshot")
        r = AnalyzerReport.objects.create(
            cortex_job_id="j1", type="url", status="Success", analyzer=a,
            level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        r.refresh_from_db()
        self.assertEqual(r.screenshot_bucket, "")
        self.assertEqual(r.screenshot_key, "")

    def test_screenshot_key_indexed(self):
        field = AnalyzerReport._meta.get_field("screenshot_key")
        self.assertTrue(field.db_index)
