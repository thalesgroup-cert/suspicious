from django.contrib.auth import get_user_model
from django.test import TestCase

from api.utils.observable_report import assemble_observables
from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.models import Analyzer, AnalyzerReport, DerivedObservable
from url_process.models import URL


class ObservableReportDerivedTests(TestCase):
    def test_child_row_has_derived_from_and_parent_has_note(self):
        group = ObservableGroup.objects.create(label="g")
        reporter = get_user_model().objects.create_user("r", "", "x")
        case = Case.objects.create(observable_group=group, reporter=reporter, description="")
        parent = URL.objects.create(address="https://tinyurl.com/x")
        child = URL.objects.create(address="https://evil.example/login")
        for u in (parent, child):
            ObservableGroupArtifact.objects.create(group=group, artifact_type="URL", url=u)
        un = Analyzer.objects.create(name="UnshortenLink_1_2", analyzer_cortex_id="UnshortenLink_1_2")
        src = AnalyzerReport.objects.create(cortex_job_id="js", type="url", status="Success",
            analyzer=un, url=parent, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={})
        DerivedObservable.objects.create(case=case, source_report=src, via_analyzer="UnshortenLink_1_2",
            parent_type="url", parent_id=parent.pk, child_type="url", child_id=child.pk,
            child_value=child.address, child_band="Dangerous",
            escalation_note="Escalated to Dangerous: UnshortenLink_1_2 extracted https://evil.example/login → Dangerous.")

        rows = {r["value"]: r for r in assemble_observables(case)}
        self.assertEqual(rows["https://evil.example/login"]["derived_from"],
                         {"value": "https://tinyurl.com/x", "via_analyzer": "UnshortenLink_1_2"})
        self.assertIn("Escalated", rows["https://tinyurl.com/x"]["escalation_note"])
        self.assertIsNone(rows["https://tinyurl.com/x"]["derived_from"])

    def test_plain_observable_has_empty_fields(self):
        group = ObservableGroup.objects.create(label="g")
        reporter = get_user_model().objects.create_user("r2", "", "x")
        case = Case.objects.create(observable_group=group, reporter=reporter, description="")
        plain = URL.objects.create(address="https://plain.example")
        ObservableGroupArtifact.objects.create(group=group, artifact_type="URL", url=plain)

        rows = {r["value"]: r for r in assemble_observables(case)}
        self.assertIsNone(rows["https://plain.example"]["derived_from"])
        self.assertEqual(rows["https://plain.example"]["escalation_note"], "")
