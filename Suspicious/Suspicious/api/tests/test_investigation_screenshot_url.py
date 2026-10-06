from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.models import Analyzer, AnalyzerReport
from url_process.models import URL


def _make_user(username):
    u = User.objects.create_user(username=username, password="pw-12345")
    g, _ = Group.objects.get_or_create(name="CERT")
    u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class InvestigationScreenshotUrlTest(TestCase):
    def setUp(self):
        self.user = _make_user("u")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

        g = ObservableGroup.objects.create()
        self.url1 = URL.objects.create(address="http://one.test")
        self.url2 = URL.objects.create(address="http://two.test")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="URL", url=self.url1)
        ObservableGroupArtifact.objects.create(group=g, artifact_type="URL", url=self.url2)
        self.case = Case.objects.create(
            description="d", reporter=self.user, observable_group=g
        )
        a = Analyzer.objects.create(
            name="Lookyloo_Screenshot", analyzer_cortex_id="lk1", tier=2
        )
        self.r1 = AnalyzerReport.objects.create(
            cortex_job_id="j", type="url", status="Success", analyzer=a,
            url=self.url1, level="safe", confidence=90, score=0,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        self.r1.screenshot_key = f"report-{self.r1.id}.png"
        self.r1.save(update_fields=["screenshot_key"])

        og = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(
            group=og, artifact_type="URL",
            url=URL.objects.create(address="http://noshot.test"),
        )
        self.other_case = Case.objects.create(
            description="d2", reporter=self.user, observable_group=og
        )

    def test_case_level_url_present_when_any_report_has_screenshot(self):
        resp = self.client.get(reverse("investigation-details", args=[self.case.id]))
        self.assertEqual(
            resp.data["screenshot_url"], f"/api/cases/{self.case.id}/screenshot.png"
        )

    def test_case_level_url_null_without_screenshots(self):
        resp = self.client.get(
            reverse("investigation-details", args=[self.other_case.id])
        )
        self.assertIsNone(resp.data["screenshot_url"])

    def test_per_observable_url(self):
        resp = self.client.get(reverse("investigation-details", args=[self.case.id]))
        obs = {o["value"]: o for o in resp.data["observable_group"]["observables"]}
        self.assertEqual(
            obs["http://one.test"]["screenshot_url"],
            f"/api/cases/{self.case.id}/screenshot.png?report={self.r1.id}",
        )
        self.assertIsNone(obs["http://two.test"]["screenshot_url"])
