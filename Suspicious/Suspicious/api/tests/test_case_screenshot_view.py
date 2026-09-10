"""GET /api/cases/<id>/screenshot.png streams a screenshot analyzer's
captured page image from MinIO, addressed by
AnalyzerReport.screenshot_bucket / screenshot_key.
"""
from unittest.mock import MagicMock, patch

from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.models import Analyzer, AnalyzerReport
from url_process.models import URL

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def _make_user(username, group="CERT"):
    u = User.objects.create_user(username=username, password="pw-12345")
    if group:
        g, _ = Group.objects.get_or_create(name=group)
        u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class CaseScreenshotViewTest(TestCase):
    def setUp(self):
        self.user = _make_user("investigator")
        self.plain_user = _make_user("outsider", group=None)
        self.client = APIClient()
        self.client.force_authenticate(self.user)

        g = ObservableGroup.objects.create()
        self.url = URL.objects.create(address="http://evil.test/page")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="URL", url=self.url)
        self.case = Case.objects.create(
            description="d", reporter=self.user, observable_group=g
        )
        self.lookyloo = Analyzer.objects.create(
            name="Lookyloo_Screenshot", analyzer_cortex_id="lky", tier=2
        )
        self.urlscan = Analyzer.objects.create(
            name="Urlscan.io_Scan", analyzer_cortex_id="us", tier=2
        )

    def _report(self, analyzer, key, bucket="screenshots"):
        return AnalyzerReport.objects.create(
            cortex_job_id="j", type="url", status="Success",
            analyzer=analyzer, url=self.url,
            level="malicious", confidence=80, score=9,
            report_summary={}, report_taxonomy={}, report_full={},
            screenshot_bucket=bucket, screenshot_key=key,
        )

    def _obj(self):
        return MagicMock(stream=lambda n: [PNG], close=lambda: None, release_conn=lambda: None)

    def _url(self, **params):
        base = reverse("case-screenshot", args=[self.case.id])
        if params:
            base += "?" + "&".join(f"{k}={v}" for k, v in params.items())
        return base

    @patch("api.views.case_screenshot.get_s3_client")
    def test_streams_png(self, client):
        client.return_value.get_object.return_value = self._obj()
        self._report(self.lookyloo, "s/look.png")

        resp = self.client.get(self._url())

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "image/png")

    def test_404_when_no_screenshot(self):
        resp = self.client.get(self._url())
        self.assertEqual(resp.status_code, 404)

    def test_403_for_non_investigator(self):
        self.client.force_authenticate(self.plain_user)
        resp = self.client.get(self._url())
        self.assertEqual(resp.status_code, 403)

    @patch("api.views.case_screenshot.get_s3_client")
    def test_prefers_lookyloo_over_urlscan(self, client):
        client.return_value.get_object.return_value = self._obj()
        self._report(self.urlscan, "s/us.png")
        self._report(self.lookyloo, "s/look.png")

        resp = self.client.get(self._url())

        self.assertEqual(resp.status_code, 200)
        client.return_value.get_object.assert_called_with("screenshots", "s/look.png")

    @patch("api.views.case_screenshot.get_s3_client")
    def test_report_query_param_selects(self, client):
        client.return_value.get_object.return_value = self._obj()
        self._report(self.lookyloo, "s/look.png")
        r2 = self._report(self.urlscan, "s/us.png")

        resp = self.client.get(self._url(report=r2.id))

        self.assertEqual(resp.status_code, 200)
        client.return_value.get_object.assert_called_with(
            r2.screenshot_bucket, r2.screenshot_key
        )

    def test_404_for_foreign_report_id(self):
        self._report(self.lookyloo, "s/look.png")
        resp = self.client.get(self._url(report=999999))
        self.assertEqual(resp.status_code, 404)
