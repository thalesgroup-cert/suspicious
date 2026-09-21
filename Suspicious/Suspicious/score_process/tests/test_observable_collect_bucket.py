from django.test import TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from score_process.scoring.observable_collect import _bucket_reports
from url_process.models import URL


class BucketReportsTests(TestCase):
    def setUp(self):
        self.a = Analyzer.objects.create(name="X", analyzer_cortex_id="X")
        self.u1 = URL.objects.create(address="https://a.test/")
        self.u2 = URL.objects.create(address="https://b.test/")

    def _rep(self, url, cid):
        return AnalyzerReport.objects.create(
            cortex_job_id=cid, type="url", status="Success", analyzer=self.a,
            url=url, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={})

    def test_buckets_by_fk_id(self):
        r1, r2 = self._rep(self.u1, "j1"), self._rep(self.u2, "j2")
        out = _bucket_reports([("k1", self.u1, "url"), ("k2", self.u2, "url")])
        self.assertEqual([r.id for r in out["k1"]], [r1.id])
        self.assertEqual([r.id for r in out["k2"]], [r2.id])

    def test_analyzed_url_representative_folds_in(self):
        self.u2.analyzed_url = self.u1
        self.u2.save(update_fields=["analyzed_url"])
        r_rep = self._rep(self.u1, "jrep")
        out = _bucket_reports([("k2", self.u2, "url")])
        self.assertIn(r_rep.id, [r.id for r in out["k2"]])

    def test_one_query(self):
        self._rep(self.u1, "j1")
        with self.assertNumQueries(1):
            _bucket_reports([("k1", self.u1, "url")])
