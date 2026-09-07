from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact, Result
from cortex_job.cortex_utils.derived_observables import score_derived_observables
from cortex_job.models import Analyzer, AnalyzerReport, DerivedObservable
from score_process.scoring.apply import finalise_ioc_group
from url_process.models import URL


def _report(analyzer, url, level, tier_name="VirusTotal_x"):
    return AnalyzerReport.objects.create(
        cortex_job_id=f"j{url.pk}-{level}", type="url", status="Success", analyzer=analyzer,
        url=url, level=level, confidence=90, score=9 if level == "malicious" else 0,
        report_summary={"taxonomies": [{"level": level}]}, report_taxonomy={}, report_full={},
    )


class DerivedScoringTests(TestCase):
    def setUp(self):
        u = get_user_model().objects.create_user("r", "", "x")
        self.group = ObservableGroup.objects.create(label="g")
        self.case = Case.objects.create(observable_group=self.group, reporter=u, description="")
        self.parent = URL.objects.create(address="https://tinyurl.com/x")
        self.child = URL.objects.create(address="https://evil.example/login")
        ObservableGroupArtifact.objects.create(group=self.group, artifact_type="URL", url=self.parent)
        ObservableGroupArtifact.objects.create(group=self.group, artifact_type="URL", url=self.child)
        self.vt = Analyzer.objects.create(name="VirusTotal_GetReport_3_1",
                                          analyzer_cortex_id="VirusTotal_GetReport_3_1", tier=1)
        self.unshorten = Analyzer.objects.create(name="UnshortenLink_1_2",
                                                 analyzer_cortex_id="UnshortenLink_1_2")
        self.src = AnalyzerReport.objects.create(
            cortex_job_id="js", type="url", status="Success", analyzer=self.unshorten,
            url=self.parent, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={"found": True, "url": self.child.address})
        DerivedObservable.objects.create(
            case=self.case, source_report=self.src, via_analyzer="UnshortenLink_1_2",
            parent_type="url", parent_id=self.parent.pk,
            child_type="url", child_id=self.child.pk, child_value=self.child.address)

    def test_malicious_child_yields_parent_escalation(self):
        _report(self.vt, self.child, "malicious")
        out = score_derived_observables(self.case)
        self.assertIn(("url", self.parent.pk), out)
        band, note = out[("url", self.parent.pk)]
        self.assertEqual(band, "Dangerous")
        self.assertIn("UnshortenLink_1_2", note)
        self.assertEqual(DerivedObservable.objects.get().child_band, "Dangerous")

    def test_safe_child_yields_nothing(self):
        _report(self.vt, self.child, "safe")
        self.assertEqual(score_derived_observables(self.case), {})

    def test_finalise_ioc_group_escalates_parent_and_group(self):
        _report(self.vt, self.child, "malicious")
        finalise_ioc_group(self.case)
        self.case.refresh_from_db()
        self.parent.refresh_from_db()
        self.assertEqual(self.parent.ioc_level, "malicious")
        self.assertEqual(self.case.results, Result.DANGEROUS)
        self.assertTrue(any("Escalated" in r for r in self.case.verdict_rationale))
