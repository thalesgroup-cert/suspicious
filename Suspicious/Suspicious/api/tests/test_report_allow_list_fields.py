from django.test import TestCase

from api.serializers.investigations import InvestigationAnalyzerReportSerializer
from api.serializers.submissions import SubmissionAnalyzerReportSerializer
from cortex_job.models import Analyzer, AnalyzerReport
from url_process.models import URL


class ReportAllowListFieldsTests(TestCase):
    def setUp(self):
        self.an = Analyzer.objects.create(name="VT", analyzer_cortex_id="vt")
        self.url = URL.objects.create(address="https://allow.example")

    def _report(self, **kw):
        return AnalyzerReport.objects.create(
            cortex_job_id="j", type="url", status="Success", analyzer=self.an, url=self.url,
            level="safe", confidence=100, score=0, report_summary={}, report_taxonomy={}, report_full={}, **kw)

    def test_both_serializers_expose_marker_and_original(self):
        pre = {"level": "malicious", "score": 10.0, "confidence": 100.0, "category": "x"}
        r = self._report(category="Safe DW triggered", pre_allowlist=pre)
        for ser in (InvestigationAnalyzerReportSerializer, SubmissionAnalyzerReportSerializer):
            d = ser(r).data
            self.assertIs(d["allow_listed"], True)
            self.assertEqual(d["pre_allowlist"], pre)

    def test_plain_report_is_not_allow_listed(self):
        d = InvestigationAnalyzerReportSerializer(self._report(category="0/93 engines")).data
        self.assertIs(d["allow_listed"], False)
        self.assertIsNone(d["pre_allowlist"])
