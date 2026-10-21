from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail, CaseHasNonFileIocs, Result
from cortex_job.models import Analyzer, AnalyzerReport
from file_process.models import File
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import Mail, MailArchive
from score_process.scoring.collect import collect_signals, collect_votes
from score_process.scoring.engine import AiSignal, Signal
from url_process.models import URL


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

        signals, ai, deny_listed, ai_missing, deny_reason = collect_signals(case)

        self.assertTrue(all(isinstance(s, Signal) for s in signals))
        self.assertEqual(len(signals), 1)
        self.assertTrue(signals[0].is_malicious)
        self.assertLessEqual(signals[0].confidence, 100)
        self.assertEqual(signals[0].confidence, 100)
        self.assertFalse(deny_listed)

    def test_signal_confidence_is_0_100_scale(self):
        from score_process.scoring.collect import _signals_from
        sigs = _signals_from([7], [70], 0, "url")
        self.assertEqual(sigs[0].confidence, 70)

    def test_no_iocs_yields_no_signals(self):
        case = Case.objects.create(description="", reporter=self.user)
        signals, ai, deny_listed, ai_missing, deny_reason = collect_signals(case)
        self.assertEqual(signals, [])
        self.assertFalse(deny_listed)
        self.assertEqual(deny_reason, "")

    def test_ai_confidence_is_already_0_100(self):
        case = Case.objects.create(
            description="", reporter=self.user, score_ai=6, confidence_ai=100,
        )
        _, ai, _, _, _ = collect_signals(case)
        self.assertIsNotNone(ai)
        self.assertEqual(ai.confidence, 100)
        self.assertEqual(ai.score, 6)

    def test_ai_confidence_clamped_to_100(self):
        case = Case.objects.create(
            description="", reporter=self.user, score_ai=6, confidence_ai=150,
        )
        _, ai, _, _, _ = collect_signals(case)
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

        signals, ai, _, ai_missing, _ = collect_signals(case)

        self.assertIsNotNone(ai)
        self.assertEqual(ai.score, 0)
        self.assertEqual(ai.confidence, 100)
        self.assertFalse(ai_missing)
        self.assertEqual(
            signals, [],
            "AI's own archive-file report leaked into the generic per-file "
            "signal list, double-counting it alongside the dedicated `ai` signal.",
        )


class CollectSignalsGroupTests(TestCase):
    def test_group_case_is_not_scored_by_collect_signals(self):
        """IOC-road (ObservableGroup) cases are finalised by
        finalise_ioc_group via the categorical engine; collect_signals must
        NOT walk the group (that would double-score the shared IOC rows)."""
        from django.contrib.auth.models import User
        from ip_process.models import IP
        from cortex_job.models import Analyzer, AnalyzerReport
        from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
        from score_process.scoring.collect import collect_signals

        u = User.objects.create_user("csg_u", password="p")
        analyzer = Analyzer.objects.create(name="Abuse", analyzer_cortex_id="Abuse", weight=1)
        g = ObservableGroup.objects.create()
        ip = IP.objects.create(address="3.3.3.3")
        AnalyzerReport.objects.create(
            cortex_job_id="jg0", type="ip", status="Success", analyzer=analyzer,
            ip=ip, level="malicious", confidence=9, score=9,
            report_summary={"taxonomies": [{"level": "malicious", "value": "abuse"}]},
            report_taxonomy={}, report_full={},
        )
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        case = Case.objects.create(description="d", reporter=u, observable_group=g)

        signals, ai, deny, ai_missing, reason = collect_signals(case)
        self.assertEqual(signals, [])


class MailEmbeddedSignalOptOutTests(TestCase):
    """When scoring.mail_embedded_categorical is ON (default), an embedded
    URL's analyzer score must NOT appear among the Signals fed to score_case —
    it is scored by the categorical path instead."""

    def _mail_case_with_embedded_bad_url(self):
        from datetime import datetime, timezone as tz
        from mail_feeder.models import MailArtifact, ArtifactIsUrl, MailBody
        from url_process.models import URL

        u = get_user_model().objects.create_user("mesoo_r", password="x")
        mail = Mail.objects.create(subject="s", reportedBy="r@x.test",
            date=datetime(2026, 1, 1, tzinfo=tz.utc), to="a@x.test", mail_id="mesoo1")
        case = Case.objects.create(description="", reporter=u)
        case.fileOrMail = CaseHasFileOrMail.objects.create(mail=mail, case=case)
        case.save()

        url = URL.objects.create(address="https://evil.test/login")
        ma = MailArtifact.objects.create(mail=mail, artifact_type="URL")
        join = ArtifactIsUrl.objects.create(url=url, artifact=ma)
        ma.artifactIsUrl = join
        ma.save(update_fields=["artifactIsUrl"])
        a = Analyzer.objects.create(name="GTI", analyzer_cortex_id="GTI", tier=1)
        AnalyzerReport.objects.create(cortex_job_id="ju", type="url", status="Success",
            analyzer=a, url=url, level="malicious", confidence=95, score=9,
            report_summary={"taxonomies": [{"level": "malicious"}]}, report_taxonomy={}, report_full={})

        # a benign mail_body report so score_case has an intrinsic signal
        body = MailBody.objects.create(body_score=2, body_confidence=60, body_level="safe",
            body_value="hi", fuzzy_hash="bh")
        mail.mail_body = body
        mail.save(update_fields=["mail_body"])
        AnalyzerReport.objects.create(cortex_job_id="jb", type="mail_body", status="Success",
            analyzer=Analyzer.objects.create(name="Yara_Boosted_3_2", analyzer_cortex_id="Yara_Boosted_3_2", tier=2),
            mail_body=body, level="safe", confidence=60, score=2,
            report_summary={}, report_taxonomy={}, report_full={})
        return case

    @patch("score_process.scoring.collect.get_config", return_value=True)
    def test_embedded_url_score_not_in_signals(self, _cfg):
        case = self._mail_case_with_embedded_bad_url()
        signals, *_ = collect_signals(case)
        self.assertFalse(any(s.score >= 8 for s in signals if not s.is_failure))

    @patch("score_process.scoring.collect.get_config", return_value=None)
    def test_flag_unset_defaults_on(self, _cfg):
        case = self._mail_case_with_embedded_bad_url()
        signals, *_ = collect_signals(case)
        self.assertFalse(any(s.score >= 8 for s in signals if not s.is_failure))

    @patch("score_process.scoring.collect.get_config", return_value=False)
    def test_flag_off_keeps_embedded_url_in_signals(self, _cfg):
        case = self._mail_case_with_embedded_bad_url()
        signals, *_ = collect_signals(case)
        self.assertTrue(any(s.score >= 8 for s in signals))  # the bad URL still votes


class CollectVotesTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="cv_u", password="x")
        self.url = URL.objects.create(address="https://a.test/1")
        self.url2 = URL.objects.create(address="https://b.test/2")
        self.url.analyzed_url = self.url2   # a case covers both URLs
        self.url.save()
        self.case = Case.objects.create(description="", reporter=self.user)
        self.case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=self.case, url=self.url)
        self.case.save()

    def _report(self, name, weight=0.2, *, url=None, job="j", status="Success", level="safe",
                score=0, confidence=100, category=""):
        analyzer, _ = Analyzer.objects.get_or_create(
            name=name, defaults={"analyzer_cortex_id": name, "weight": weight})
        return AnalyzerReport.objects.create(
            cortex_job_id=f"{name}-{job}", type="url", status=status, analyzer=analyzer,
            url=url or self.url, level=level, score=score, confidence=confidence,
            category=category, report_summary={"x": 1}, report_taxonomy={}, report_full={})

    def _votes(self, ai=None):
        with patch("cortex_job.cortex_utils.cortex_and_job_management._get_cortex_config",
                   return_value={"analyzers": {"ai": "AIMailAnalyzer"}}):
            return {v.analyzer: v for v in collect_votes(self.case, ai)}

    def _allow(self, address="a.test"):
        from domain_process.models import Domain
        from settings.models import AllowListDomain
        AllowListDomain.objects.create(domain=Domain.objects.create(value=address), user=self.user)

    def test_whitelisted_safe_and_dangerous_votes(self):
        self._allow()
        self._report("WL", 0.3, category="Safe DW triggered")
        self._report("Clean", 0.2)
        self._report("Bad", 0.5, level="malicious", score=10)
        v = self._votes()
        self.assertEqual((v["WL"].band, v["WL"].whitelisted, v["WL"].weight), ("Safe", True, 0.3))
        self.assertEqual((v["Clean"].band, v["Clean"].whitelisted), ("Safe", False))
        self.assertEqual((v["Bad"].band, v["Bad"].whitelisted), ("Dangerous", False))

    def test_failed_pending_info_low_confidence_and_zero_weight_are_not_votes(self):
        self._report("Failed", status="Failure")
        self._report("Pending", status="InProgress")
        self._report("Info", level="info", score=2, confidence=50)
        self._report("Unsure", level="suspicious", score=7, confidence=49)
        self._report("Zero", 0)
        self.assertEqual(self._votes(), {})

    def test_allow_listed_domain_later_campaign_or_deny_listed_is_not_whitelisted(self):
        from domain_process.models import Domain
        from settings.models import CampaignDomainAllowList, DenyListDomain
        self._allow("a.test")
        d = Domain.objects.get(value="a.test")
        for model in (CampaignDomainAllowList, DenyListDomain):
            self._report("Late", 0.3, category="Safe DW triggered")
            self.assertTrue(self._votes()["Late"].whitelisted)
            row = model.objects.create(domain=d, user=self.user)
            self.assertFalse(self._votes()["Late"].whitelisted)
            row.delete()

    def test_stored_marker_without_a_live_allow_list_entry_is_not_whitelisted(self):
        self._report("Stale", 0.3, category="Safe DW triggered")
        self.assertFalse(self._votes()["Stale"].whitelisted)

    def test_analyzer_flagging_one_target_and_whitelisted_on_another_votes_dissent(self):
        self._allow()
        self._report("Both", category="Safe DW triggered")
        self._report("Both", url=self.url2, level="malicious", score=10, job="2")
        vote = self._votes()["Both"]
        self.assertEqual((vote.band, vote.whitelisted), ("Dangerous", False))

    def test_a_newer_rerun_replaces_a_stale_dissent(self):
        self._report("Re", level="malicious", score=10, job="old")
        self._report("Re", job="new")
        self.assertEqual(self._votes()["Re"].band, "Safe")

    def test_ai_signal_votes_with_the_ai_analyzer_weight(self):
        Analyzer.objects.create(name="AIMailAnalyzer", analyzer_cortex_id="ai", weight=0.4)
        ai = self._votes(AiSignal(score=9, confidence=90))["AIMailAnalyzer"]
        self.assertEqual((ai.band, ai.weight), ("Dangerous", 0.4))
        self.assertNotIn("AIMailAnalyzer", self._votes(AiSignal(score=9, confidence=10)))
        self.assertNotIn("AIMailAnalyzer", self._votes(None))
