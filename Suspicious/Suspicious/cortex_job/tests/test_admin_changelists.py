from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from case_handler.models import Case
from cortex_job.models import Analyzer, AnalyzerReport


class AdminChangelistTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_superuser("adm", "a@x.io", "pw")
        cls.analyzer = Analyzer.objects.create(name="A1", analyzer_cortex_id="cx1")
        AnalyzerReport.objects.create(
            cortex_job_id="j1", type="url", status="Success", analyzer=cls.analyzer,
            level="info", confidence=1, score=1,
            report_summary={}, report_taxonomy=[], report_full={"big": "x"},
        )
        Case.objects.create(description="d", reporter=cls.admin)

    def setUp(self):
        self.client.force_login(self.admin)

    def test_analyzer_search_does_not_crash(self):
        r = self.client.get(reverse("admin:cortex_job_analyzer_changelist"), {"q": "A1"})
        self.assertEqual(r.status_code, 200)

    def test_report_changelist_defers_blobs_and_form_still_loads(self):
        r = self.client.get(reverse("admin:cortex_job_analyzerreport_changelist"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("report_full", r.context["cl"].queryset.query.deferred_loading[0])
        rid = AnalyzerReport.objects.get().pk
        r = self.client.get(reverse("admin:cortex_job_analyzerreport_change", args=[rid]))
        self.assertEqual(r.status_code, 200)

    def test_case_search_by_id(self):
        r = self.client.get(reverse("admin:case_handler_case_changelist"), {"q": str(Case.objects.get().pk)})
        self.assertEqual(r.status_code, 200)
