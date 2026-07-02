"""Tests for plan_url_analysis — Task 4 of the URL Analysis Planner."""
import uuid
from contextlib import contextmanager
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from url_process.models import URL
from url_process.url_utils.url_planner import plan_url_analysis


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mk(address, **kw):
    return URL.objects.create(address=address, **kw)


def _mk_analyzer():
    """Create the minimum Analyzer row needed to build AnalyzerReport rows."""
    from cortex_job.models import Analyzer
    return Analyzer.objects.create(
        name="TestAnalyzer",
        analyzer_cortex_id="test-analyzer-1",
    )


def _mk_report(url, analyzer):
    """Create a minimal AnalyzerReport for *url* using *analyzer*."""
    from cortex_job.models import AnalyzerReport
    return AnalyzerReport.objects.create(
        url=url,
        analyzer=analyzer,
        cortex_job_id=f"job-test-{uuid.uuid4().hex[:8]}",
        type="url",
        status="Success",
        level="info",
        confidence=0.9,
        score=0.5,
        report_summary={},
        report_taxonomy={},
        report_full={},
    )


@contextmanager
def override_config(**kw):
    """Patch settings.config.get_config used inside url_planner."""
    from url_process.url_utils import url_planner

    def fake(key, default=None):
        short = key.split(".")[-1]
        if short in kw:
            return kw[short]
        return default

    with mock.patch.object(url_planner, "get_config", fake, create=True):
        yield


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class PlanUrlAnalysisTest(TestCase):
    def test_within_case_collapse(self):
        a = _mk("https://x.com/p?id=1")
        b = _mk("https://x.com/p?id=2")
        plan = plan_url_analysis([a, b])
        # one representative analyzed, the other reused → it
        self.assertEqual(len(plan.to_analyze), 1)
        self.assertEqual(len(plan.to_reuse), 1)
        reused_row, rep = plan.to_reuse[0]
        self.assertEqual(rep, plan.to_analyze[0])
        self.assertEqual(reused_row.analysis_status, URL.AnalysisStatus.REUSED)
        self.assertEqual(reused_row.analyzed_url_id, rep.id)

    def test_distinct_paths_both_analyzed(self):
        a = _mk("https://x.com/a")
        b = _mk("https://x.com/b")
        plan = plan_url_analysis([a, b])
        self.assertEqual(len(plan.to_analyze), 2)

    def test_per_domain_cap(self):
        urls = [_mk(f"https://x.com/p{i}") for i in range(8)]
        with override_config(max_per_domain=3):
            plan = plan_url_analysis(urls)
        self.assertEqual(len(plan.to_analyze), 3)
        self.assertEqual(len(plan.skipped), 5)
        for s in plan.skipped:
            self.assertEqual(s.analysis_status, URL.AnalysisStatus.SKIPPED)

    def test_payload_in_query_survives_cap(self):
        # 3 boring + 1 open-redirect; cap=1 must keep the redirect one
        boring = [_mk(f"https://x.com/a{i}") for i in range(3)]
        redirect = _mk("https://x.com/go?redirect=http://evil.com")
        with override_config(max_per_domain=1):
            plan = plan_url_analysis(boring + [redirect])
        self.assertIn(redirect, plan.to_analyze)
        self.assertEqual(len(plan.to_analyze), 1)
        for b in boring:
            self.assertIn(b, plan.skipped)

    def test_cross_case_ttl_hit_reuses(self):
        analyzer = _mk_analyzer()
        prior = _mk("https://x.com/p?id=9", analysis_status=URL.AnalysisStatus.ANALYZED)
        prior.canonical_key = "https://x.com/p?id"
        prior.save(update_fields=["canonical_key"])
        _mk_report(prior, analyzer)
        fresh = _mk("https://x.com/p?id=10")
        with override_config(reuse_ttl_days=7):
            plan = plan_url_analysis([fresh])
        self.assertEqual(len(plan.to_reuse), 1)
        self.assertEqual(plan.to_reuse[0][1], prior)
        fresh.refresh_from_db()
        self.assertEqual(fresh.analysis_status, URL.AnalysisStatus.REUSED)
        self.assertEqual(fresh.analyzed_url_id, prior.id)

    def test_cross_case_ttl_miss_analyzes(self):
        from cortex_job.models import AnalyzerReport
        analyzer = _mk_analyzer()
        old = _mk("https://x.com/p?id=9", analysis_status=URL.AnalysisStatus.ANALYZED)
        old.canonical_key = "https://x.com/p?id"
        old.save(update_fields=["canonical_key"])
        report = _mk_report(old, analyzer)
        # Back-date the report beyond the TTL window
        AnalyzerReport.objects.filter(pk=report.pk).update(
            creation_date=timezone.now() - timedelta(days=30)
        )
        fresh = _mk("https://x.com/p?id=10")
        with override_config(reuse_ttl_days=7):
            plan = plan_url_analysis([fresh])
        self.assertEqual(len(plan.to_analyze), 1)

    def test_fail_open_on_bad_url(self):
        bad = _mk("http://[::bad::]/")
        plan = plan_url_analysis([bad])
        # never dropped — ends up analyzed
        self.assertIn(bad, plan.to_analyze)
        self.assertEqual(len(plan.skipped), 0)
        self.assertEqual(len(plan.to_reuse), 0)

    def test_multiple_unparseable_urls_not_collapsed(self):
        a = _mk("http://[::bad::]/")
        b = _mk("http://[::worse::]/")
        plan = plan_url_analysis([a, b])
        self.assertIn(a, plan.to_analyze)
        self.assertIn(b, plan.to_analyze)
        self.assertEqual(len(plan.to_reuse), 0)
