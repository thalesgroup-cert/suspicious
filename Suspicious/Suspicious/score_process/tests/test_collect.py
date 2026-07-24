from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail, CaseHasNonFileIocs, Result
from cortex_job.models import Analyzer, AnalyzerReport
from file_process.models import File
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import Mail, MailArchive
from score_process.scoring.collect import collect_signals
from score_process.scoring.engine import Signal


class CollectSignalsTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="cs_u", password="x")

    def test_ioc_only_case_yields_one_signal(self):
        ip = IP.objects.create(address="203.0.113.7")
        analyzer = Analyzer.objects.create(name="Abuse", analyzer_cortex_id="Abuse", weight=1)
        AnalyzerReport.objects.create(
            cortex_job_id="j1", type="ip", status="Success", analyzer=analyzer,
            ip=ip, level="malicious", confidence=9, score=9,
            report_summary={"taxonomies": [{"level": "malicious", "value": "abuse"}]},
            report_taxonomy={}, report_full={},
        )
        case = Case.objects.create(description="", reporter=self.user)
        iocs = CaseHasNonFileIocs.objects.create(case=case, ip=ip)
        case.nonFileIocs = iocs
        case.save()

        signals, ai, deny_listed, ai_missing = collect_signals(case)

        self.assertTrue(all(isinstance(s, Signal) for s in signals))
        self.assertEqual(len(signals), 1)
        self.assertTrue(signals[0].is_malicious)
        self.assertLessEqual(signals[0].confidence, 100)
        self.assertEqual(signals[0].confidence, 100)
        self.assertFalse(deny_listed)

    def test_no_iocs_yields_no_signals(self):
        case = Case.objects.create(description="", reporter=self.user)
        signals, ai, deny_listed, ai_missing = collect_signals(case)
        self.assertEqual(signals, [])
        self.assertFalse(deny_listed)

    def test_ai_confidence_is_already_0_100(self):
        case = Case.objects.create(
            description="", reporter=self.user, score_ai=6, confidence_ai=100,
        )
        _, ai, _, _ = collect_signals(case)
        self.assertIsNotNone(ai)
        self.assertEqual(ai.confidence, 100)
        self.assertEqual(ai.score, 6)

    def test_ai_confidence_clamped_to_100(self):
        case = Case.objects.create(
            description="", reporter=self.user, score_ai=6, confidence_ai=150,
        )
        _, ai, _, _ = collect_signals(case)
        self.assertEqual(ai.confidence, 100)

    def test_ai_report_on_archive_file_not_double_counted_as_generic_signal(self):
        """Regression (prod case 61682): AI_Mail_Analyzer attaches its own
        AnalyzerReport to the mail archive's `file` (cortex_and_job_management.py
        manage_ai_jobs), which is the *same* value collect_signals already
        surfaces separately via case.score_ai/confidence_ai as `ai`. Without
        excluding it, that one report also gets pulled into the generic
        per-file weighted signal, inflating base_conf to tie ai.confidence —
        which silences the AI override in score_case() on ties and lets a
        low-confidence neutral signal elsewhere decide the case instead.
        """
        from settings.config import get_section

        mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m-ai-dup",
        )
        archive_file = File.objects.create(
            linked_hash=Hash.objects.create(value="dup-archive-hash"), tmp_path="x.eml",
        )
        MailArchive.objects.create(mail=mail, archive=archive_file)

        ai_name = get_section("integrations.cortex").get("analyzers", {}).get("ai")
        ai_analyzer = Analyzer.objects.create(
            analyzer_cortex_id="ai-dup-1", name=ai_name, weight=1.0,
        )
        AnalyzerReport.objects.create(
            cortex_job_id="job-ai-dup", type="file", status="Success", analyzer=ai_analyzer,
            file=archive_file, level="safe", confidence=100, score=0,
            report_summary={}, report_full={}, report_taxonomy={},
        )

        case = Case.objects.create(
            description="", reporter=self.user, score_ai=0, confidence_ai=100,
            results_ai=Result.SAFE, category_ai="Internal",
        )
        fm = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.fileOrMail = fm
        case.save(update_fields=["fileOrMail"])

        signals, ai, _, ai_missing = collect_signals(case)

        self.assertIsNotNone(ai)
        self.assertEqual(ai.score, 0)
        self.assertEqual(ai.confidence, 100)
        self.assertFalse(ai_missing)
        self.assertEqual(
            signals, [],
            "AI's own archive-file report leaked into the generic per-file "
            "signal list, double-counting it alongside the dedicated `ai` signal.",
        )
