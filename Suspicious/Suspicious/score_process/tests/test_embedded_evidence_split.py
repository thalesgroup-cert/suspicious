"""Characterization of `_apply_embedded_escalation` across the evidence/escalation split
(Plan F, Task 4): same verdict, same IOC and artifact levels as before the split."""
from unittest.mock import patch

from django.test import TestCase

from case_handler.models import Result
from cortex_job.models import Analyzer
from mail_feeder.models import MailArtifact
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
from score_process.tests import test_mail_embedded_escalation as base
from url_process.models import URL

UNTOUCHED = ("info", 5.0, 0.0, "info", 5.0, 0.0)


class EmbeddedEvidenceSplitTests(TestCase):
    setUp = base.MailEmbeddedEscalationTests.setUp
    _rep = base.MailEmbeddedEscalationTests._rep
    _verdict = base.MailEmbeddedEscalationTests._verdict

    def _run(self, band):
        return CortexAnalyzerReports._apply_embedded_escalation(self.case, self.mail, self._verdict(band))

    def _levels(self):
        url = URL.objects.get(pk=self.url.pk)
        ma = MailArtifact.objects.get(pk=self.ma.pk)
        return (url.ioc_level, url.ioc_score, url.ioc_confidence,
                ma.artifact_level, ma.artifact_score, ma.artifact_confidence)

    def test_no_embedded_reports(self):
        v_in = self._verdict(Result.SAFE)
        self.assertIs(CortexAnalyzerReports._apply_embedded_escalation(self.case, self.mail, v_in), v_in)
        self.assertEqual(self._levels(), UNTOUCHED)

    def test_dangerous_child_raises_safe(self):
        self._rep(self.gti, "malicious", 95, 9)
        v = self._run(Result.SAFE)
        self.assertEqual((v.result, v.final_score, v.final_confidence, v.n_scored, v.rule),
                         (Result.DANGEROUS, 2, 60, 2, "embedded-ioc-escalation"))
        self.assertEqual(self._levels(), ("malicious", 9.0, 60.0, "malicious", 9.0, 60.0))

    def test_body_less_mail_with_suspicious_child(self):
        tier2 = Analyzer.objects.create(name="T2", analyzer_cortex_id="T2", tier=2)
        self._rep(tier2, "suspicious", 80, 6)
        v = self._run(Result.FAILURE)
        self.assertEqual((v.result, v.final_score, v.n_scored, v.rule),
                         (Result.SUSPICIOUS, 6, 2, "embedded-ioc-escalation"))
        self.assertEqual(self._levels()[0], "suspicious")
        self.assertEqual(self._levels()[3], "suspicious")

    def test_sticky_allow_listed_observable(self):
        URL.objects.filter(pk=self.url.pk).update(ioc_level="SAFE-ALLOW_LISTED", ioc_score=0, ioc_confidence=100)
        self._rep(self.gti, "malicious", 95, 9)
        v = self._run(Result.SAFE)
        self.assertEqual(v.result, Result.DANGEROUS)
        self.assertEqual(self._levels(), ("SAFE-ALLOW_LISTED", 0.0, 100.0, "malicious", 9.0, 60.0))

    def test_evidence_is_none_without_embedded_reports(self):
        self.assertIsNone(CortexAnalyzerReports._embedded_evidence(self.case, self.mail))

    def test_escalate_is_pure_and_matches_the_composition(self):
        self._rep(self.gti, "malicious", 95, 9)
        evidence = CortexAnalyzerReports._embedded_evidence(self.case, self.mail)
        with patch.object(URL, "save") as url_save, patch.object(MailArtifact, "save") as ma_save:
            first = CortexAnalyzerReports._escalate(self._verdict(Result.SAFE), evidence)
            second = CortexAnalyzerReports._escalate(self._verdict(Result.SAFE), evidence)
        url_save.assert_not_called()
        ma_save.assert_not_called()
        self.assertEqual(first, second)
        self.assertEqual(first, self._run(Result.SAFE))

    @patch("settings.config.get_config", side_effect=base._flag_off)
    def test_kill_switch_off_uses_derived_escalation(self, _cfg):
        self._rep(self.gti, "malicious", 95, 9)
        v_in = self._verdict(Result.SAFE)
        self.assertIs(CortexAnalyzerReports._apply_embedded_escalation(self.case, self.mail, v_in), v_in)
        self.assertEqual(self._levels(), UNTOUCHED)
