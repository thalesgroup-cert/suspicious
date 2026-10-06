"""dedupe_verdict_explanation_sources repairs Case.verdict_explanation for
cases whose sources were built by the pre-fix, undeduplicated queryset
(score_process/scoring/{apply.py,cortex_analyzers/reports.py}) -- one row
per historical analyzer run instead of one per (analyzer, target). Never
re-derives the verdict: reuses the already-locked band/confidence/rule."""
from io import StringIO

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.core.management import call_command
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

_BLOATED_SOURCES = [
    {"name": "GTI", "tier": 1, "verdict": "malicious", "counted": True, "note": "old run"},
    {"name": "GTI", "tier": 1, "verdict": "malicious", "counted": True, "note": ""},
    {"name": "GTI", "tier": 1, "verdict": "malicious", "counted": True, "note": ""},
]


class DedupeVerdictExplanationSourcesTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="dvs_u", password="x")
        self.analyzer = Analyzer.objects.create(
            name="GTI", analyzer_cortex_id="gti1", tier=1, weight=0.9,
        )

    def _mail_case(self, bloated=True, addr="203.0.113.50", reruns=3):
        mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t",
            mail_id=f"dvs-mail-{addr}",
        )
        hash_obj = Hash.objects.create(value=f"dvs-hash-{addr}")
        archive = File.objects.create(linked_hash=hash_obj, tmp_path=f"dvs-{addr}.tar.gz")
        MailArchive.objects.create(mail=mail, archive=archive)

        ip = IP.objects.create(address=addr)
        for i in range(reruns):
            AnalyzerReport.objects.create(
                cortex_job_id=f"dvs-{addr}-run{i}", type="ip", status="Success",
                analyzer=self.analyzer, ip=ip, level="malicious", confidence=95, score=10,
                report_summary={}, report_taxonomy={}, report_full={},
            )
        case = Case.objects.create(
            description="", reporter=self.user, results=Result.DANGEROUS,
            final_confidence=95,
            verdict_explanation={
                "band": "Dangerous", "confidence": 95, "decisive_rule": "single-strong-signal",
                "analyst_paragraph": "stale", "reporter_paragraph": "stale",
                "confidence_reading": "stale",
                "sources": _BLOATED_SOURCES[:reruns] if bloated else _BLOATED_SOURCES[:1],
            },
        )
        fm = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.fileOrMail = fm
        iocs = CaseHasNonFileIocs.objects.create(case=case, ip=ip)
        case.nonFileIocs = iocs
        case.save()
        return case

    def _ioc_case(self, n_observables=1):
        group = ObservableGroup.objects.create()
        urls = []
        for i in range(n_observables):
            url = URL.objects.create(address=f"http://evil{i}.test/x")
            ObservableGroupArtifact.objects.create(group=group, artifact_type="URL", url=url)
            urls.append(url)
            for j in range(2):  # two runs each, to make dedup observable
                AnalyzerReport.objects.create(
                    cortex_job_id=f"dvs-ioc-{i}-{j}", type="url", status="Success",
                    analyzer=self.analyzer, url=url, level="malicious", confidence=95,
                    score=10, report_summary={}, report_taxonomy={}, report_full={},
                )
        case = Case.objects.create(
            description="", reporter=self.user, observable_group=group,
            results=Result.DANGEROUS, final_confidence=95,
            verdict_explanation={
                "band": "Dangerous", "confidence": 95, "decisive_rule": "group-worst-of",
                "analyst_paragraph": "stale", "reporter_paragraph": "stale",
                "confidence_reading": "stale",
                "sources": _BLOATED_SOURCES * n_observables,
            },
        )
        return case

    def test_dedupes_bloated_mail_case_sources(self):
        case = self._mail_case(reruns=3)
        call_command("dedupe_verdict_explanation_sources", stdout=StringIO())
        case.refresh_from_db()
        ve = case.verdict_explanation
        self.assertEqual(len(ve["sources"]), 1)
        self.assertEqual(ve["decisive_rule"], "single-strong-signal")  # preserved, not re-derived
        self.assertEqual(ve["band"], "Dangerous")  # preserved, not re-derived
        self.assertNotEqual(ve["analyst_paragraph"], "stale")  # recomposed to match new source count

    def test_dry_run_writes_nothing(self):
        case = self._mail_case(reruns=3)
        out = StringIO()
        call_command("dedupe_verdict_explanation_sources", "--dry-run", stdout=out)
        case.refresh_from_db()
        self.assertEqual(len(case.verdict_explanation["sources"]), 3)
        self.assertIn("would repair 1", out.getvalue())

    def test_skips_already_clean_case(self):
        case = self._mail_case(bloated=False, reruns=1)
        out = StringIO()
        call_command("dedupe_verdict_explanation_sources", stdout=out)
        case.refresh_from_db()
        self.assertEqual(case.verdict_explanation["sources"], _BLOATED_SOURCES[:1])
        self.assertIn("already clean 1", out.getvalue())

    def test_single_observable_ioc_case_is_repaired(self):
        case = self._ioc_case(n_observables=1)
        call_command("dedupe_verdict_explanation_sources", stdout=StringIO())
        case.refresh_from_db()
        self.assertEqual(len(case.verdict_explanation["sources"]), 1)

    def test_multi_observable_group_case_needs_manual_review(self):
        case = self._ioc_case(n_observables=2)
        out = StringIO()
        call_command("dedupe_verdict_explanation_sources", stdout=out)
        case.refresh_from_db()
        # untouched -- still has the bloated, pre-repair source list
        self.assertEqual(len(case.verdict_explanation["sources"]), len(_BLOATED_SOURCES) * 2)
        self.assertIn("needs manual review 1", out.getvalue())
        self.assertIn(str(case.id), out.getvalue())

    def test_idempotent(self):
        case = self._mail_case(reruns=3)
        call_command("dedupe_verdict_explanation_sources", stdout=StringIO())
        case.refresh_from_db()
        first = case.verdict_explanation
        out = StringIO()
        call_command("dedupe_verdict_explanation_sources", stdout=out)
        case.refresh_from_db()
        self.assertEqual(case.verdict_explanation, first)
        self.assertIn("already clean 1", out.getvalue())

    def test_case_id_filters_to_one_case(self):
        case1 = self._mail_case(addr="203.0.113.60", reruns=3)
        case2 = self._mail_case(addr="203.0.113.61", reruns=3)
        call_command(
            "dedupe_verdict_explanation_sources", "--case-id", str(case1.id),
            stdout=StringIO(),
        )
        case1.refresh_from_db()
        case2.refresh_from_db()
        self.assertEqual(len(case1.verdict_explanation["sources"]), 1)
        self.assertEqual(len(case2.verdict_explanation["sources"]), 3)  # untouched
