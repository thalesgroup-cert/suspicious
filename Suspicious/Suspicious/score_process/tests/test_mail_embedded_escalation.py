"""`_apply_embedded_escalation` — a mail case's embedded observables scored by
the categorical trust engine (Task 5).

Each embedded observable is scored on its OWN analyzer reports via
`score_observable`; the mail band is raised to the worst embedded band and the
analyzers' rationale folded into `verdict.rationale`. Per-observable `ioc_*`
(global) and per-`MailArtifact` `artifact_*` (case-scoped) levels are written.
"""
from datetime import datetime, timezone as tz
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from settings.config import get_config as _real_get_config


def _flag_off(key, *a, **kw):
    """get_config side_effect: only the categorical flag is forced False."""
    return False if key == "scoring.mail_embedded_categorical" else _real_get_config(key, *a, **kw)

from case_handler.models import Case, CaseHasFileOrMail, Result
from cortex_job.models import Analyzer, AnalyzerReport
from mail_feeder.models import Mail, MailArtifact, ArtifactIsUrl
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
from url_process.models import URL


def _mail_url_artifact(mail, url):
    """A MailArtifact wired in BOTH FK directions (mail_observable_reports reads
    MailArtifact.artifactIsUrl, admin filters traverse it too)."""
    ma = MailArtifact.objects.create(mail=mail, artifact_type="URL")
    join = ArtifactIsUrl.objects.create(url=url, artifact=ma)
    ma.artifactIsUrl = join
    ma.save(update_fields=["artifactIsUrl"])
    return ma


class MailEmbeddedEscalationTests(TestCase):
    def setUp(self):
        u = get_user_model().objects.create_user("r", "", "x")
        self.mail = Mail.objects.create(
            subject="s", reportedBy="r@x.test",
            date=datetime(2026, 1, 1, tzinfo=tz.utc), to="a@x.test", mail_id="m1",
        )
        self.case = Case.objects.create(description="", reporter=u)
        self.case.fileOrMail = CaseHasFileOrMail.objects.create(mail=self.mail, case=self.case)
        self.case.save()
        self.url = URL.objects.create(address="https://evil.test/login")
        self.ma = _mail_url_artifact(self.mail, self.url)
        self.gti = Analyzer.objects.create(
            name="GoogleThreatIntelligence_GetReport",
            analyzer_cortex_id="GoogleThreatIntelligence_GetReport", tier=1,
        )
        self.urlscan = Analyzer.objects.create(
            name="Urlscan_io_Search_0_1_1",
            analyzer_cortex_id="Urlscan_io_Search_0_1_1", tier=3,
        )

    def _rep(self, analyzer, level, conf, score):
        return AnalyzerReport.objects.create(
            cortex_job_id=f"j{analyzer.pk}", type="url", status="Success",
            analyzer=analyzer, url=self.url, level=level, confidence=conf, score=score,
            report_summary={"taxonomies": [{"level": level}]}, report_taxonomy={}, report_full={})

    def _verdict(self, band):
        from score_process.scoring.engine import CaseVerdict
        return CaseVerdict(final_score=2, final_confidence=30, result=band,
                           n_malicious=0, n_scored=1)

    def test_tier1_malicious_url_escalates_inconclusive_mail_to_dangerous(self):
        self._rep(self.gti, "malicious", 95, 9)
        self._rep(self.urlscan, "suspicious", 60, 6)
        v = CortexAnalyzerReports._apply_embedded_escalation(
            self.case, self.mail, self._verdict(Result.INCONCLUSIVE))
        self.assertEqual(v.result, Result.DANGEROUS)
        self.assertTrue(any("authoritative" in r.lower() or "GoogleThreatIntelligence" in r
                            for r in v.rationale))
        ma = MailArtifact.objects.get(artifactIsUrl__url=self.url)
        self.assertEqual(ma.artifact_level, "malicious")
        self.url.refresh_from_db()
        self.assertEqual(self.url.ioc_level, "malicious")

    def test_tier1_clean_beats_tier3_suspicious_no_escalation(self):
        self._rep(self.gti, "safe", 95, 0)
        self._rep(self.urlscan, "suspicious", 60, 6)
        v = CortexAnalyzerReports._apply_embedded_escalation(
            self.case, self.mail, self._verdict(Result.SAFE))
        self.assertEqual(v.result, Result.SAFE)

    def test_no_embedded_reports_returns_verdict_untouched(self):
        v_in = self._verdict(Result.SAFE)
        self.assertIs(
            CortexAnalyzerReports._apply_embedded_escalation(self.case, self.mail, v_in),
            v_in)

    def test_sticky_mail_artifact_keeps_its_level(self):
        MailArtifact.objects.filter(artifactIsUrl__url=self.url).update(artifact_level="SAFE-ALLOW_LISTED")
        self._rep(self.gti, "malicious", 95, 9)
        CortexAnalyzerReports._apply_embedded_escalation(
            self.case, self.mail, self._verdict(Result.INCONCLUSIVE))
        ma = MailArtifact.objects.get(artifactIsUrl__url=self.url)
        self.assertEqual(ma.artifact_level, "SAFE-ALLOW_LISTED")

    def test_sticky_ioc_level_keeps_score_and_confidence(self):
        """A sticky global row skips the WHOLE re-score, not just the level."""
        URL.objects.filter(pk=self.url.pk).update(
            ioc_level="critical", ioc_score=3.0, ioc_confidence=11.0)
        self._rep(self.gti, "malicious", 95, 9)
        CortexAnalyzerReports._apply_embedded_escalation(
            self.case, self.mail, self._verdict(Result.INCONCLUSIVE))
        self.url.refresh_from_db()
        self.assertEqual(self.url.ioc_level, "critical")
        self.assertEqual(self.url.ioc_score, 3.0)
        self.assertEqual(self.url.ioc_confidence, 11.0)

    def test_failure_base_verdict_still_escalates_on_embedded_evidence(self):
        """A body-less mail scores Result.FAILURE (no scorable signal); an
        embedded Tier-1 malicious verdict must still raise the band."""
        self._rep(self.gti, "malicious", 95, 9)
        v = CortexAnalyzerReports._apply_embedded_escalation(
            self.case, self.mail, self._verdict(Result.FAILURE))
        self.assertEqual(v.result, Result.DANGEROUS)
        self.assertTrue(v.rationale)

    def test_failure_base_verdict_unchanged_when_embedded_is_clean(self):
        """Body-less mail + one clean Tier-1 embedded URL → no band raise, so
        the FAILURE verdict is not rebased."""
        self._rep(self.gti, "safe", 95, 0)
        v = CortexAnalyzerReports._apply_embedded_escalation(
            self.case, self.mail, self._verdict(Result.FAILURE))
        self.assertEqual(v.result, Result.FAILURE)

    @patch("settings.config.get_config", side_effect=_flag_off)
    def test_flag_off_falls_back_to_derived_escalation(self, _cfg):
        with patch.object(CortexAnalyzerReports, "_apply_derived_escalation",
                          return_value="FALLBACK") as fb:
            out = CortexAnalyzerReports._apply_embedded_escalation(
                self.case, self.mail, self._verdict(Result.SAFE))
        fb.assert_called_once()
        self.assertEqual(out, "FALLBACK")
