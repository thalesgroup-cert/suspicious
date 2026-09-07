"""Mail-road parent escalation for derived observables (Task 8).

On the mail road a derived child is itself a MailArtifact, so its analyzer
reports already move the case verdict on their own. The wiring's added value is:
  1. bump the parent MailArtifact.artifact_level to the child's band
  2. an explicit rationale line naming the extraction
"""
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

    def test_malicious_derived_child_escalates_parent_artifact_and_rationale(self):
        self._child_report("malicious", 9)

        CortexAnalyzerReports.get_report(self.case)

        self.case.refresh_from_db()
        self.parent_ma.refresh_from_db()
        self.assertEqual(self.parent_ma.artifact_level, "malicious")
        self.assertTrue(any("Escalated to Dangerous" in r for r in self.case.verdict_rationale))
        self.assertTrue(any("UnshortenLink_1_2" in r for r in self.case.verdict_rationale))

    def test_suspicious_derived_child_escalates_parent_artifact_and_rationale(self):
        self._child_report("suspicious", 6)

        CortexAnalyzerReports.get_report(self.case)

        self.case.refresh_from_db()
        self.parent_ma.refresh_from_db()
        self.assertEqual(self.parent_ma.artifact_level, "suspicious")
        self.assertTrue(any("Escalated to Suspicious" in r for r in self.case.verdict_rationale))
        self.assertTrue(any("UnshortenLink_1_2" in r for r in self.case.verdict_rationale))

    def test_allow_listed_parent_artifact_keeps_its_level(self):
        self._child_report("malicious", 9)
        MailArtifact.objects.filter(pk=self.parent_ma.pk).update(
            artifact_level="SAFE-ALLOW_LISTED"
        )

        CortexAnalyzerReports.get_report(self.case)

        self.parent_ma.refresh_from_db()
        self.assertEqual(self.parent_ma.artifact_level, "SAFE-ALLOW_LISTED")
