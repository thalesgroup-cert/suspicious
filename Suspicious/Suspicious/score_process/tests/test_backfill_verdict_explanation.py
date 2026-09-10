"""Task 8: the backfill_verdict_explanation command populates a best-effort
generic (rule="unknown") explanation on finalized cases that predate the
feature. It does not re-run scoring, --dry-run writes nothing, and it is
idempotent."""
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from case_handler.lifecycle import LifecycleState
from case_handler.models import (
    Case, ObservableGroup, ObservableGroupArtifact, Result,
)
from cortex_job.models import Analyzer, AnalyzerReport
from url_process.models import URL


class BackfillVerdictExplanationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="bve_u", password="x")
        self.analyzer = Analyzer.objects.create(
            name="GTI", analyzer_cortex_id="gti1", tier=1, weight=0.9,
        )

    def _finalized_case(self, addr="http://evil.test/x", job="bve1"):
        url = URL.objects.create(address=addr)
        group = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(group=group, artifact_type="URL", url=url)
        case = Case.objects.create(
            description="t", reporter=self.user, observable_group=group,
            results=Result.DANGEROUS, final_confidence=95,
            lifecycle_state=LifecycleState.FINALIZED, verdict_explanation=None,
        )
        AnalyzerReport.objects.create(
            cortex_job_id=job, type="url", status="Success", analyzer=self.analyzer,
            url=url, level="malicious", confidence=95, score=10,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        return case

    def test_backfills_null_explanation(self):
        case = self._finalized_case()
        call_command("backfill_verdict_explanation", stdout=StringIO())
        case.refresh_from_db()
        ve = case.verdict_explanation
        self.assertIsInstance(ve, dict)
        self.assertEqual(ve["decisive_rule"], "unknown")
        self.assertEqual(ve["band"], "Dangerous")
        self.assertTrue(ve["analyst_paragraph"])
        self.assertTrue(ve["sources"])

    def test_dry_run_writes_nothing(self):
        case = self._finalized_case()
        out = StringIO()
        call_command("backfill_verdict_explanation", "--dry-run", stdout=out)
        case.refresh_from_db()
        self.assertIsNone(case.verdict_explanation)
        self.assertIn("would write 1", out.getvalue())

    def test_skips_non_finalized_case(self):
        case = self._finalized_case()
        case.lifecycle_state = LifecycleState.SCORING
        case.save(update_fields=["lifecycle_state"])
        call_command("backfill_verdict_explanation", stdout=StringIO())
        case.refresh_from_db()
        self.assertIsNone(case.verdict_explanation)

    def test_idempotent(self):
        case = self._finalized_case()
        call_command("backfill_verdict_explanation", stdout=StringIO())
        case.refresh_from_db()
        first = case.verdict_explanation
        out = StringIO()
        call_command("backfill_verdict_explanation", stdout=out)
        case.refresh_from_db()
        self.assertEqual(case.verdict_explanation, first)
        self.assertIn("scanned 0", out.getvalue())

    def test_limit_honoured(self):
        self._finalized_case(addr="http://a.test/1", job="bve-a")
        self._finalized_case(addr="http://b.test/2", job="bve-b")
        call_command("backfill_verdict_explanation", "--limit", "1", stdout=StringIO())
        self.assertEqual(
            Case.objects.filter(verdict_explanation__isnull=True).count(), 1,
        )
