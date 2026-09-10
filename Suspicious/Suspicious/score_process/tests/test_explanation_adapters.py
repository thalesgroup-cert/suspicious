from uuid import uuid4

from django.test import TestCase

from case_handler.models import Result
from cortex_job.models import Analyzer, AnalyzerReport, URL
from score_process.scoring.engine import CaseVerdict
from score_process.scoring.observable_engine import GroupVerdict, ObservableVerdict
from score_process.scoring.explanation.adapters import (
    explain_mail_case,
    explain_observable_group,
)


def _analyzer(name, tier=3, weight=0.2):
    return Analyzer.objects.create(
        name=name, analyzer_cortex_id=uuid4().hex, tier=tier, weight=weight,
    )


def _report(analyzer, level="malicious", status="Success", category="malware", confidence=90):
    u = URL.objects.create(address="http://x.test")
    return AnalyzerReport.objects.create(
        cortex_job_id="j", type="url", status=status, analyzer=analyzer, url=u,
        level=level, confidence=confidence, score=0, category=category,
        report_summary={}, report_taxonomy={}, report_full={},
    )


class AdapterTest(TestCase):
    def test_observable_group_basic(self):
        gti = _report(_analyzer("GTI", tier=1), level="malicious")
        ctx = _report(_analyzer("Whois", tier=3), level="safe", category="")
        ve = explain_observable_group(
            None,
            GroupVerdict("Dangerous", 90, {"malicious": 1}, ["worst-of"], rule="group-worst-of"),
            [ObservableVerdict("Dangerous", 90, None, {"malicious": 1}, ["x"],
                               rule="tier1-authoritative-malicious")],
            reports=[gti, ctx],
        )
        self.assertEqual(ve.band, "Dangerous")
        self.assertEqual(ve.confidence, 90)
        self.assertEqual(ve.decisive_rule, "group-worst-of")
        self.assertTrue(ve.analyst_paragraph)
        self.assertTrue(ve.reporter_paragraph)
        self.assertEqual(ve.sources[0].name, "GTI")
        self.assertTrue(ve.sources[0].counted)
        self.assertFalse(ve.sources[1].counted)
        self.assertEqual(ve.sources[0].note, "malware")

    def test_single_observable_uses_escalated_rule(self):
        rep = _report(_analyzer("GTI", tier=1), level="malicious")
        ve = explain_observable_group(
            None, None,
            [ObservableVerdict("Dangerous", 77, None, {"malicious": 1}, ["x"],
                               rule="tier1-authoritative-malicious")],
            reports=[rep],
        )
        self.assertEqual(ve.decisive_rule, "tier1-authoritative-malicious")
        self.assertEqual(ve.band, "Dangerous")
        self.assertEqual(ve.confidence, 77)
        self.assertTrue(ve.sources[0].counted)

    def test_empty_case_is_thin_coverage(self):
        ve = explain_observable_group(None, None, [], reports=[])
        self.assertEqual(ve.decisive_rule, "thin-coverage")
        self.assertEqual(ve.band, "Inconclusive")
        self.assertEqual(ve.confidence, 0)
        self.assertEqual(ve.sources, ())

    def test_mail_escalation_rule_flows(self):
        rep = _report(_analyzer("mail_analyzer_ai", tier=2), level="malicious")
        ve = explain_mail_case(
            None,
            CaseVerdict(7, 80, "Dangerous", 1, 3, rule="embedded-ioc-escalation"),
            analyzer_reports=[rep],
            embedded_verdicts=[],
        )
        self.assertEqual(ve.decisive_rule, "embedded-ioc-escalation")
        self.assertEqual(ve.band, "Dangerous")
        self.assertEqual(ve.confidence, 80)
        self.assertTrue(ve.sources[0].counted)

    def test_mail_band_from_result_enum(self):
        rep = _report(_analyzer("VirusTotal", tier=1), level="safe", category="")
        ve = explain_mail_case(
            None,
            CaseVerdict(1.0, 30.0, Result.SUSPICIOUS, 0, 2, rule="weighted-consensus"),
            analyzer_reports=[rep],
            embedded_verdicts=[],
        )
        self.assertEqual(ve.band, "Suspicious")
        self.assertEqual(ve.confidence, 30)

    def test_failed_report_marked_failed_and_not_counted(self):
        ok = _report(_analyzer("GTI", tier=1), level="malicious")
        bad = _report(_analyzer("Sandbox", tier=2), status="Failure", level="")
        ve = explain_observable_group(
            None,
            GroupVerdict("Dangerous", 60, {"malicious": 1}, ["worst-of"], rule="group-worst-of"),
            [],
            reports=[ok, bad],
        )
        by_name = {s.name: s for s in ve.sources}
        self.assertEqual(by_name["Sandbox"].verdict, "failed")
        self.assertFalse(by_name["Sandbox"].counted)
