"""Task 7: the explanation adapters are called at case finalisation on both
scoring roads and the result is stored on Case.verdict_explanation — and an
explanation failure never breaks finalisation."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import (
    Case, CaseHasFileOrMail, CaseHasNonFileIocs, ObservableGroup,
    ObservableGroupArtifact, Result,
)
from cortex_job.models import Analyzer, AnalyzerReport
from file_process.models import File
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import Mail, MailArchive
from url_process.models import URL
from score_process.scoring.apply import finalise_ioc_group
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports


class ExplanationFinalizationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="ef_u", password="x")
        self.analyzer = Analyzer.objects.create(
            name="GTI", analyzer_cortex_id="gti1", tier=1, weight=0.9,
        )

    def _ioc_group_case(self):
        url = URL.objects.create(address="http://evil.test/x")
        group = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(group=group, artifact_type="URL", url=url)
        case = Case.objects.create(
            description="t", reporter=self.user, observable_group=group,
        )
        AnalyzerReport.objects.create(
            cortex_job_id="ef1", type="url", status="Success", analyzer=self.analyzer,
            url=url, level="malicious", confidence=95, score=10,
            report_summary={"taxonomies": [{"level": "malicious", "value": "gti"}]},
            report_taxonomy={}, report_full={},
        )
        return case

    def test_ioc_group_finalisation_stores_explanation(self):
        case = self._ioc_group_case()

        finalise_ioc_group(case)

        case.refresh_from_db()
        self.assertEqual(case.results, Result.DANGEROUS)
        ve = case.verdict_explanation
        self.assertIsInstance(ve, dict)
        self.assertEqual(ve["band"], "Dangerous")
        self.assertTrue(ve["decisive_rule"])
        self.assertTrue(ve["analyst_paragraph"])

    def test_ioc_explanation_failure_does_not_break_finalisation(self):
        case = self._ioc_group_case()

        with patch(
            "score_process.scoring.explanation.adapters.explain_observable_group",
            side_effect=RuntimeError("boom"),
        ):
            finalise_ioc_group(case)

        case.refresh_from_db()
        self.assertEqual(case.results, Result.DANGEROUS)
        self.assertEqual(case.final_score, 9)
        self.assertIsNone(case.verdict_explanation)

    def test_mail_case_finalisation_stores_explanation(self):
        mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="ef-mail-1",
        )
        hash_obj = Hash.objects.create(value="ef-mail-hash")
        archive = File.objects.create(linked_hash=hash_obj, tmp_path="ef-mail.tar.gz")
        MailArchive.objects.create(mail=mail, archive=archive)

        ip = IP.objects.create(address="203.0.113.44")
        AnalyzerReport.objects.create(
            cortex_job_id="ef2", type="ip", status="Success", analyzer=self.analyzer,
            ip=ip, level="malicious", confidence=95, score=10,
            report_summary={"taxonomies": [{"level": "malicious", "value": "gti"}]},
            report_taxonomy={}, report_full={},
        )
        case = Case.objects.create(description="", reporter=self.user)
        fm = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.fileOrMail = fm
        iocs = CaseHasNonFileIocs.objects.create(case=case, ip=ip)
        case.nonFileIocs = iocs
        case.save()

        CortexAnalyzerReports.get_report(case)

        case.refresh_from_db()
        self.assertEqual(case.results, Result.DANGEROUS)
        ve = case.verdict_explanation
        self.assertIsInstance(ve, dict)
        self.assertEqual(ve["band"], "Dangerous")
        self.assertTrue(ve["decisive_rule"])
        self.assertTrue(ve["analyst_paragraph"])
