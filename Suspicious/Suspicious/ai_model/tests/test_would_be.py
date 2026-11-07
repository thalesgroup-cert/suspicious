"""The would-be verdict of a shadow answer (Plan F, Task 4, Ruling F5/F6)."""
from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from ai_model import registry
from ai_model.models import AiAssessment, ShadowResult
from ai_model.tests.test_registry import cand
from case_handler.models import CaseHasNonFileIocs, Result
from connectors.tests.test_provider_dispatch import make_mail_case
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from mail_feeder.models import MailArtifact
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
from score_process.tests.test_mail_embedded_escalation import _flag_off, _mail_url_artifact
from url_process.models import URL

LIVE_FIELDS = ("results", "final_score", "final_confidence", "score", "confidence", "analysis_done",
               "is_denylisted", "list_reason", "inconclusive_reason", "verdict_rationale",
               "results_ai", "score_ai", "confidence_ai")
SHADOW = {"SAFE": 1, "DANGEROUS": 9, "INCONCLUSIVE": 5}


class WouldBeTest(TestCase):
    n = 0

    def setUp(self):
        self.version = registry.set_shadow(cand("s1", manifest={"eligible": True}))
        self.ip_analyzer = Analyzer.objects.create(name="IpA", analyzer_cortex_id="IpA", weight=1)
        self.url_analyzer = Analyzer.objects.create(
            name="GoogleThreatIntelligence_GetReport",
            analyzer_cortex_id="GoogleThreatIntelligence_GetReport", tier=1)

    def mail_case(self, ai_result="Safe", ai_score=2, shadow=None):
        """A mail case whose live AI (90%) outweighs one 50% Safe IP report, with one embedded
        URL scored Safe by a Tier-1 analyzer, and optionally a stored shadow answer."""
        type(self).n += 1
        n = self.n
        case, _ = make_mail_case(n)
        ip = IP.objects.create(address=f"198.51.100.{n}")
        AnalyzerReport.objects.create(
            cortex_job_id=f"ip{n}", type="ip", status="Success", analyzer=self.ip_analyzer, ip=ip,
            level="safe", confidence=50, score=1, report_summary={}, report_taxonomy={}, report_full={})
        url = URL.objects.create(address=f"https://ok{n}.test/")
        _mail_url_artifact(case.fileOrMail.mail, url)
        AnalyzerReport.objects.create(
            cortex_job_id=f"url{n}", type="url", status="Success", analyzer=self.url_analyzer, url=url,
            level="safe", confidence=95, score=0, report_summary={"taxonomies": [{"level": "safe"}]},
            report_taxonomy={}, report_full={})
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, ip=ip)
        case.results_ai, case.score_ai, case.confidence_ai = ai_result, ai_score, 90
        case.save()
        if shadow:
            ShadowResult.objects.create(case=case, version=self.version, result=shadow,
                                        score=SHADOW[shadow], confidence=95)
        return case

    def run_report(self, case):
        CortexAnalyzerReports.get_report(case)
        case.refresh_from_db()
        return case

    def row(self, case):
        return ShadowResult.objects.get(case=case)

    def test_the_would_be_verdict_and_a_critical_flip_are_stored(self):
        case = self.run_report(self.mail_case(shadow="DANGEROUS"))
        row = self.row(case)
        self.assertEqual(case.results, Result.SAFE)
        self.assertEqual((row.live_result, row.would_be_result, row.would_be_score,
                          row.would_be_confidence, row.would_be_rule, row.flip),
                         (Result.SAFE, Result.DANGEROUS, 9, 95, "ai-classifier-decisive", "critical"))

    def test_a_shadow_dangerous_gives_the_verdict_the_engine_gives_for_that_ai_signal(self):
        with_shadow = self.run_report(self.mail_case(shadow="DANGEROUS"))
        live_dangerous = self.run_report(self.mail_case(ai_result="Dangerous", ai_score=9))
        live_dangerous.confidence_ai = 95
        live_dangerous.save(update_fields=["confidence_ai"])
        live_dangerous = self.run_report(live_dangerous)
        row = self.row(with_shadow)
        self.assertEqual((row.would_be_result, row.would_be_score, row.would_be_confidence, row.would_be_rule),
                         (live_dangerous.results, live_dangerous.final_score,
                          live_dangerous.final_confidence, "ai-classifier-decisive"))

    def test_dangerous_to_safe_is_critical(self):
        row = self.row(self.run_report(self.mail_case("Dangerous", 9, shadow="SAFE")))
        self.assertEqual((row.live_result, row.would_be_result, row.flip),
                         (Result.DANGEROUS, Result.SAFE, "critical"))

    def test_same_verdict_is_no_flip(self):
        row = self.row(self.run_report(self.mail_case(shadow="SAFE")))
        self.assertEqual((row.live_result, row.would_be_result, row.flip), (Result.SAFE, Result.SAFE, "none"))

    def test_suspicious_to_dangerous_is_changed_not_critical(self):
        row = self.row(self.run_report(self.mail_case("Suspicious", 6, shadow="DANGEROUS")))
        self.assertEqual((row.live_result, row.would_be_result, row.flip),
                         (Result.SUSPICIOUS, Result.DANGEROUS, "changed"))

    def test_a_shadow_inconclusive_is_a_missing_ai(self):
        row = self.row(self.run_report(self.mail_case(shadow="INCONCLUSIVE")))
        self.assertEqual((row.would_be_result, row.would_be_rule, row.flip),
                         (Result.INCONCLUSIVE, "analysis-incomplete", "changed"))

    def test_the_live_case_is_identical_with_and_without_a_shadow(self):
        def fields(case):
            return tuple(getattr(case, f) for f in LIVE_FIELDS)
        plain = self.run_report(self.mail_case())
        shadowed = self.run_report(self.mail_case(shadow="DANGEROUS"))
        self.assertEqual(fields(plain), fields(shadowed))
        self.assertFalse(AiAssessment.objects.exists())

    def test_the_evidence_is_read_once(self):
        def saves(case):
            real_url, real_ip, real_ma = URL.save, IP.save, MailArtifact.save
            with mock.patch.object(URL, "save", autospec=True, side_effect=real_url) as u, \
                    mock.patch.object(IP, "save", autospec=True, side_effect=real_ip) as i, \
                    mock.patch.object(MailArtifact, "save", autospec=True, side_effect=real_ma) as m:
                self.run_report(case)
            return u.call_count, i.call_count, m.call_count
        plain = saves(self.mail_case())
        shadowed_case = self.mail_case(shadow="DANGEROUS")
        self.assertEqual(saves(shadowed_case), plain)
        self.assertNotEqual(plain[0], 0)
        self.assertEqual(self.row(shadowed_case).would_be_result, Result.DANGEROUS)

    @mock.patch("settings.config.get_config", side_effect=_flag_off)
    def test_kill_switch_off_leaves_the_would_be_fields_empty(self, _cfg):
        derived = CortexAnalyzerReports._apply_derived_escalation
        with mock.patch.object(CortexAnalyzerReports, "_apply_derived_escalation",
                               side_effect=derived) as spy:
            plain = self.run_report(self.mail_case())
            case = self.run_report(self.mail_case(shadow="DANGEROUS"))
        self.assertEqual(spy.call_count, 2)
        self.assertEqual((case.results, case.final_score, case.final_confidence, case.verdict_rationale),
                         (plain.results, plain.final_score, plain.final_confidence, plain.verdict_rationale))
        self.assertEqual(case.results, Result.SAFE)
        row = self.row(case)
        self.assertEqual((row.live_result, row.would_be_result, row.would_be_score, row.would_be_rule, row.flip),
                         ("", "", None, "", "none"))

    def test_a_would_be_failure_is_swallowed_by_class_and_the_live_verdict_stored(self):
        with mock.patch("ai_model.shadow.record_would_be", side_effect=RuntimeError("secret mail")), \
                self.assertLogs("tasp.cron.update_ongoing_case_jobs", "WARNING") as logs:
            case = self.run_report(self.mail_case(shadow="DANGEROUS"))
        self.assertIn("RuntimeError", "".join(logs.output))
        self.assertNotIn("secret", "".join(logs.output))
        self.assertEqual(case.results, Result.SAFE)
        self.assertTrue(case.kpi_counted)

    def test_an_error_inside_record_would_be_is_swallowed(self):
        with mock.patch("ai_model.shadow.score_case", side_effect=ValueError("secret")), \
                self.assertLogs("tasp.cron.update_ongoing_case_jobs", "WARNING") as logs:
            case = self.run_report(self.mail_case(shadow="DANGEROUS"))
        self.assertIn("ValueError", "".join(logs.output))
        self.assertNotIn("secret", "".join(logs.output))
        self.assertEqual(case.results, Result.SAFE)
        self.assertEqual(self.row(case).would_be_result, "")

    def test_no_shadow_row_costs_one_existence_check(self):
        def count(case, skip):
            with CaptureQueriesContext(connection) as ctx:
                if skip:
                    with mock.patch("ai_model.shadow.record_would_be"):
                        self.run_report(case)
                else:
                    self.run_report(case)
            return len(ctx.captured_queries)
        self.run_report(self.mail_case())   # warm the config and analyzer caches
        self.assertEqual(count(self.mail_case(), skip=False) - count(self.mail_case(), skip=True), 1)
