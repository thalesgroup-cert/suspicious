import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, ObservableGroup
from connectors.contrib.ai_narration.adapters import case_to_verdict_dict
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP

from connectors.contrib.ai_narration.adapters import analyzer_reports_for_prompt


class CaseToVerdictDictTest(TestCase):
    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r", password="x")
        group = ObservableGroup.objects.create(label="g")
        self.case = Case.objects.create(
            observable_group=group, reporter=reporter, description="",
            results="Dangerous", final_score=9.2, final_confidence=88,
        )

    def test_uses_decisive_rule_from_verdict_explanation(self):
        self.case.verdict_explanation = {"band": "Dangerous", "confidence": 88, "decisive_rule": "embedded-ioc-escalation"}
        self.case.save(update_fields=["verdict_explanation"])
        result = case_to_verdict_dict(self.case)
        self.assertEqual(result, {
            "band": "Dangerous", "score": 9.2, "confidence": 88, "rule": "embedded-ioc-escalation",
        })

    def test_rule_is_unknown_when_no_verdict_explanation(self):
        result = case_to_verdict_dict(self.case)
        self.assertEqual(result["rule"], "unknown")
        self.assertEqual(result["band"], "Dangerous")
        self.assertEqual(result["score"], 9.2)
        self.assertEqual(result["confidence"], 88)

    def test_raises_on_unknown_band(self):
        self.case.results = "Failure"
        self.case.save(update_fields=["results"])
        with self.assertRaises(ValueError):
            case_to_verdict_dict(self.case)


class AnalyzerReportsForPromptTest(TestCase):
    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r2", password="x")
        self.group = ObservableGroup.objects.create(label="g2")
        self.case = Case.objects.create(
            observable_group=self.group, reporter=reporter, description="",
            results="Dangerous", final_score=9.2, final_confidence=88,
        )
        self.ip = IP.objects.create(address="8.8.8.8")
        from case_handler.models import ObservableGroupArtifact
        ObservableGroupArtifact.objects.create(
            group=self.group, artifact_type="IP", ip=self.ip
        )
        self.analyzer = Analyzer.objects.create(
            name="GTI_Lookup", analyzer_cortex_id="gti1", tier=1
        )

    def test_caps_at_twenty_reports(self):
        for i in range(25):
            ip = IP.objects.create(address=f"8.8.8.{i % 256}")
            from case_handler.models import ObservableGroupArtifact
            ObservableGroupArtifact.objects.create(
                group=self.group, artifact_type="IP", ip=ip
            )
            AnalyzerReport.objects.create(
                cortex_job_id=f"j{i}", type="ip", status="Success", analyzer=self.analyzer,
                ip=ip, level="malicious", confidence=90, score=10,
                report_summary={}, report_taxonomy={}, report_full={"n": i},
            )
        result = analyzer_reports_for_prompt(self.case)
        self.assertEqual(len(result), 20)

    def test_truncates_report_full_over_char_cap(self):
        big = {"payload": "x" * 5000}
        AnalyzerReport.objects.create(
            cortex_job_id="j-big", type="ip", status="Success", analyzer=self.analyzer,
            ip=self.ip, level="malicious", confidence=90, score=10,
            report_summary={}, report_taxonomy={}, report_full=big,
        )
        result = analyzer_reports_for_prompt(self.case)
        self.assertEqual(len(result), 1)
        report_full = result[0]["report_full"]
        self.assertTrue(report_full["_truncated"])
        self.assertEqual(report_full["original_size_chars"], len(json.dumps(big)))
        self.assertLessEqual(len(report_full["preview"]), 4000)

    def test_small_report_full_passes_through_unchanged(self):
        small = {"positives": 3, "total": 70}
        AnalyzerReport.objects.create(
            cortex_job_id="j-small", type="ip", status="Success", analyzer=self.analyzer,
            ip=self.ip, level="malicious", confidence=90, score=10,
            report_summary={}, report_taxonomy={}, report_full=small,
        )
        result = analyzer_reports_for_prompt(self.case)
        self.assertEqual(result, [{"analyzer": "GTI_Lookup", "report_full": small}])
