from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase

from case_handler.models import Case
from cortex_job.models import Analyzer, AnalyzerReport, DerivedObservable
from url_process.models import URL


class DerivedObservableModelTests(TestCase):
    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r", password="x")
        self.case = Case.objects.create(reporter=reporter)
        self.analyzer = Analyzer.objects.create(
            name="UnshortenLink_1_2", analyzer_cortex_id="UnshortenLink_1_2"
        )
        self.parent = URL.objects.create(address="https://tinyurl.com/x")
        self.child = URL.objects.create(address="https://evil.example/login")
        self.report = AnalyzerReport.objects.create(
            cortex_job_id="j1", type="url", status="Success", analyzer=self.analyzer,
            url=self.parent, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={"found": True},
        )

    def _make(self, **kw):
        defaults = dict(
            case=self.case, source_report=self.report, via_analyzer="UnshortenLink_1_2",
            parent_type="url", parent_id=self.parent.pk,
            child_type="url", child_id=self.child.pk,
            child_value="https://evil.example/login",
        )
        defaults.update(kw)
        return DerivedObservable.objects.create(**defaults)

    def test_row_persists_with_defaults(self):
        d = self._make()
        self.assertEqual(d.child_band, "")
        self.assertEqual(d.escalation_note, "")
        self.assertEqual(self.case.derived_observables.count(), 1)

    def test_same_report_child_pair_is_unique(self):
        self._make()
        with self.assertRaises(IntegrityError):
            self._make()

    def test_different_child_same_report_is_allowed(self):
        self._make()
        other = URL.objects.create(address="https://evil.example/2")
        self._make(child_id=other.pk, child_value="https://evil.example/2")
        self.assertEqual(DerivedObservable.objects.count(), 2)
