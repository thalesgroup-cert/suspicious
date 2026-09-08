"""Mail-road embedded-observable escalation, end to end through get_report.

On the mail road a derived child is itself a MailArtifact. With the categorical
merge (Task 5, `scoring.mail_embedded_categorical` default-ON) every embedded
observable is scored on its own analyzer reports via `score_observable`:
  1. its own MailArtifact.artifact_level is set to its band
  2. the case band is raised to the worst embedded band with the analyzers'
     rationale (e.g. "VirusTotal_GetReport_3_1 (authoritative) reports malicious")

Flag OFF → `_apply_derived_escalation` (Phase B): the parent MailArtifact is
bumped to the child's band instead — covered by the last test.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail, Result
from cortex_job.models import Analyzer, AnalyzerReport, DerivedObservable
from mail_feeder.models import Mail, MailArtifact, ArtifactIsUrl
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
from url_process.models import URL


def _mail_artifact(mail, url):
    ma = MailArtifact.objects.create(mail=mail, artifact_type="URL")
    join = ArtifactIsUrl.objects.create(url=url, artifact=ma)
    ma.artifactIsUrl = join
    ma.save(update_fields=["artifactIsUrl"])
    return ma


class MailDerivedEscalationTests(TestCase):
    def setUp(self):
        u = get_user_model().objects.create_user("r", "", "x")
        self.mail = Mail.objects.create(
            subject="s", reportedBy="r@x.test", date=timezone.now(),
            to="a@x.test", mail_id="m1",
        )
        self.case = Case.objects.create(reporter=u, description="")
        self.case.fileOrMail = CaseHasFileOrMail.objects.create(mail=self.mail, case=self.case)
        self.case.save()

        self.parent = URL.objects.create(address="https://tinyurl.com/x")
        self.parent_ma = _mail_artifact(self.mail, self.parent)
        self.child = URL.objects.create(address="https://evil.example/login")
        _mail_artifact(self.mail, self.child)

        self.vt = Analyzer.objects.create(
            name="VirusTotal_GetReport_3_1",
            analyzer_cortex_id="VirusTotal_GetReport_3_1", tier=1, weight=1,
        )
        self.unshorten = Analyzer.objects.create(
            name="UnshortenLink_1_2", analyzer_cortex_id="UnshortenLink_1_2", weight=1,
        )
        src = AnalyzerReport.objects.create(
            cortex_job_id="js", type="url", status="Success", analyzer=self.unshorten,
            url=self.parent, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={},
            report_full={"found": True, "url": self.child.address},
        )
        DerivedObservable.objects.create(
            case=self.case, source_report=src, via_analyzer="UnshortenLink_1_2",
            parent_type="url", parent_id=self.parent.pk,
            child_type="url", child_id=self.child.pk, child_value=self.child.address,
        )

    def _child_report(self, level, score):
        AnalyzerReport.objects.create(
            cortex_job_id=f"jc-{level}", type="url", status="Success", analyzer=self.vt,
            url=self.child, level=level, confidence=90, score=score,
            report_summary={"taxonomies": [{"level": level}]},
            report_taxonomy={}, report_full={},
        )

    def _child_ma(self):
        return MailArtifact.objects.get(artifactIsUrl__url=self.child)

    def test_malicious_child_bumps_its_own_mail_artifact_level(self):
        self._child_report("malicious", 9)

        CortexAnalyzerReports.get_report(self.case)

        self.assertEqual(self._child_ma().artifact_level, "malicious")

    def test_malicious_child_escalates_case_with_analyzer_named_rationale(self):
        self._child_report("malicious", 9)

        CortexAnalyzerReports.get_report(self.case)

        self.case.refresh_from_db()
        self.assertEqual(self.case.results, Result.DANGEROUS)
        self.assertTrue(self.case.verdict_rationale)
        self.assertTrue(any("VirusTotal_GetReport_3_1" in r
                            for r in self.case.verdict_rationale))

    def test_suspicious_child_bumps_its_own_mail_artifact_level(self):
        self._child_report("suspicious", 6)

        CortexAnalyzerReports.get_report(self.case)

        self.assertEqual(self._child_ma().artifact_level, "suspicious")

    def test_suspicious_child_escalates_case_with_analyzer_named_rationale(self):
        self._child_report("suspicious", 6)

        CortexAnalyzerReports.get_report(self.case)

        self.case.refresh_from_db()
        self.assertEqual(self.case.results, Result.SUSPICIOUS)
        self.assertTrue(any("VirusTotal_GetReport_3_1" in r
                            for r in self.case.verdict_rationale))

    @patch("settings.config.get_config", return_value=False)
    def test_flag_off_falls_back_to_parent_artifact_bump(self, _cfg):
        """Flag OFF → _apply_derived_escalation: the *parent* MailArtifact is
        bumped to the derived child's band (Phase B behaviour)."""
        self._child_report("malicious", 9)

        CortexAnalyzerReports.get_report(self.case)

        self.parent_ma.refresh_from_db()
        self.assertEqual(self.parent_ma.artifact_level, "malicious")

    def test_allow_listed_parent_artifact_keeps_its_level(self):
        self._child_report("malicious", 9)
        MailArtifact.objects.filter(pk=self.parent_ma.pk).update(
            artifact_level="SAFE-ALLOW_LISTED"
        )

        CortexAnalyzerReports.get_report(self.case)

        self.parent_ma.refresh_from_db()
        self.assertEqual(self.parent_ma.artifact_level, "SAFE-ALLOW_LISTED")
