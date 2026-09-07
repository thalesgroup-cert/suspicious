from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.cortex_utils.derived_observables import ingest_derived_observables
from cortex_job.models import Analyzer, AnalyzerReport, DerivedObservable
from url_process.models import URL


class IngestTests(TestCase):
    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r", password="x")
        self.group = ObservableGroup.objects.create(label="g")
        self.case = Case.objects.create(
            observable_group=self.group, reporter=reporter, description=""
        )
        self.parent = URL.objects.create(address="https://tinyurl.com/x")
        ObservableGroupArtifact.objects.create(
            group=self.group, artifact_type="URL", url=self.parent
        )
        self.unshorten = Analyzer.objects.create(
            name="UnshortenLink_1_2", analyzer_cortex_id="UnshortenLink_1_2")
        self.report = AnalyzerReport.objects.create(
            cortex_job_id="j1", type="url", status="Success", analyzer=self.unshorten,
            url=self.parent, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={},
            report_full={"found": True, "url": "https://evil.example/login"},
        )

    @patch("cortex_job.cortex_utils.derived_observables.CortexJob")
    def test_creates_observable_artifact_provenance_and_dispatches(self, MockCortex):
        MockCortex.return_value.launch_cortex_jobs.return_value = ["r1", "r2"]
        n = ingest_derived_observables(self.case)
        self.assertEqual(n, 1)
        child = URL.objects.get(address="https://evil.example/login")
        self.assertTrue(self.group.artifacts.filter(url=child).exists())
        d = DerivedObservable.objects.get(case=self.case)
        self.assertEqual((d.parent_type, d.parent_id), ("url", self.parent.pk))
        self.assertEqual((d.child_type, d.child_id), ("url", child.pk))
        MockCortex.return_value.launch_cortex_jobs.assert_called_once()

    @patch("cortex_job.cortex_utils.derived_observables.CortexJob")
    def test_second_call_is_a_noop(self, MockCortex):
        MockCortex.return_value.launch_cortex_jobs.return_value = ["r1"]
        ingest_derived_observables(self.case)
        MockCortex.return_value.launch_cortex_jobs.reset_mock()
        self.assertEqual(ingest_derived_observables(self.case), 0)
        MockCortex.return_value.launch_cortex_jobs.assert_not_called()

    @patch("cortex_job.cortex_utils.derived_observables.CortexJob")
    def test_one_hop_cap(self, MockCortex):
        """A report filed against a URL that is itself a derived child is not re-ingested."""
        MockCortex.return_value.launch_cortex_jobs.return_value = ["r1"]
        ingest_derived_observables(self.case)          # gen-1 child created
        child = URL.objects.get(address="https://evil.example/login")
        AnalyzerReport.objects.create(
            cortex_job_id="j2", type="url", status="Success", analyzer=self.unshorten,
            url=child, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={},
            report_full={"found": True, "url": "https://evil.example/second-hop"},
        )
        MockCortex.return_value.launch_cortex_jobs.reset_mock()
        self.assertEqual(ingest_derived_observables(self.case), 0)
        self.assertFalse(
            URL.objects.filter(address="https://evil.example/second-hop").exists()
        )

    @patch("cortex_job.cortex_utils.derived_observables.CortexJob")
    @patch("cortex_job.cortex_utils.derived_observables.get_config", return_value=False)
    def test_disabled_is_noop(self, _cfg, MockCortex):
        self.assertEqual(ingest_derived_observables(self.case), 0)

    @patch("cortex_job.cortex_utils.derived_observables.CortexJob")
    def test_ssrf_child_is_dropped(self, MockCortex):
        self.report.report_full = {"found": True, "url": "http://169.254.169.254/latest"}
        self.report.save(update_fields=["report_full"])
        self.assertEqual(ingest_derived_observables(self.case), 0)
        self.assertFalse(DerivedObservable.objects.exists())

    @patch("cortex_job.cortex_utils.derived_observables.CortexJob")
    def test_bad_extracted_value_is_skipped_not_fatal(self, MockCortex):
        """One extracted value that blows up mid-processing skips; the rest proceed."""
        MockCortex.return_value.launch_cortex_jobs.return_value = ["r1"]
        good = URL.objects.create(address="https://evil.example/good")
        two_values = lambda _full: [
            ("https://evil.example/bad", "url"),
            ("https://evil.example/good", "url"),
        ]
        with patch.dict(
            "cortex_job.cortex_utils.derived_observables.EXTRACTORS",
            {"UnshortenLink_1_2": two_values},
        ), patch(
            "cortex_job.cortex_utils.derived_observables._resolve_observable",
            side_effect=[UnicodeError("bad host"), good],
        ):
            n = ingest_derived_observables(self.case)
        self.assertEqual(n, 1)
        d = DerivedObservable.objects.get(case=self.case)
        self.assertEqual((d.child_type, d.child_id), ("url", good.pk))
