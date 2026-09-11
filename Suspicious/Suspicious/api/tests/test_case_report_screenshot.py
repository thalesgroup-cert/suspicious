"""Downloadable HTML report embeds analyzer screenshots as base64 data URIs
(a downloaded file can't authenticate to /api/…), capped at _REPORT_IMG_CAP.
"""
from unittest.mock import MagicMock, patch

from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.models import Analyzer, AnalyzerReport
from url_process.models import URL

_PNG = b"\x89PNG\r\n\x1a\n"


def _make_user(username):
    u = User.objects.create_user(username=username, password="pw-12345")
    g, _ = Group.objects.get_or_create(name="CERT")
    u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class CaseReportScreenshotTests(TestCase):
    def setUp(self):
        self.user = _make_user("u")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

        g = ObservableGroup.objects.create()
        self.group = g
        self.analyzer = a = Analyzer.objects.create(
            name="Lookyloo_Screenshot", analyzer_cortex_id="lk1", tier=2
        )
        for i in range(3):
            url = URL.objects.create(address=f"http://obs{i}.test")
            ObservableGroupArtifact.objects.create(
                group=g, artifact_type="URL", url=url
            )
            rep = AnalyzerReport.objects.create(
                cortex_job_id=f"j{i}", type="url", status="Success", analyzer=a,
                url=url, level="safe", confidence=90, score=0,
                report_summary={}, report_taxonomy={}, report_full={},
            )
            rep.screenshot_bucket = "shots"
            rep.screenshot_key = f"report-{rep.id}.png"
            rep.save(update_fields=["screenshot_bucket", "screenshot_key"])

        self.case = Case.objects.create(
            description="d", reporter=self.user, observable_group=g, results="Safe"
        )

    def _get(self):
        return self.client.get(f"/api/cases/{self.case.id}/report/?format=html")

    @patch("api.views.case_report.get_s3_client")
    def test_screenshot_inlined_as_data_uri(self, get_client):
        get_client.return_value.get_object.return_value = MagicMock(
            read=lambda: _PNG + b"\x00" * 16
        )
        body = self._get().content.decode()
        self.assertIn("data:image/png;base64,", body)
        self.assertEqual(body.count("data:image/png;base64,"), 3)

    @patch("api.views.case_report.get_s3_client")
    def test_cap_stops_further_images(self, get_client):
        big = _PNG + b"\x00" * (3 * 1024 * 1024)
        get_client.return_value.get_object.return_value = MagicMock(read=lambda: big)
        body = self._get().content.decode()
        self.assertLessEqual(body.count("data:image/png;base64,"), 2)
        self.assertIn("Screenshot omitted from the report", body)

    @patch("api.views.case_report.get_s3_client")
    def test_cap_stops_minio_fetches(self, get_client):
        # 2.5 MB per image against the 6 MB cap: the size does NOT divide the cap
        # evenly, so the running total never lands exactly on it. Rows 1-2 embed
        # (5 MB), row 3's fetch overshoots and spends the budget, and every row
        # after that must be skipped BEFORE touching MinIO.
        url = URL.objects.create(address="http://obs3.test")
        ObservableGroupArtifact.objects.create(
            group=self.group, artifact_type="URL", url=url
        )
        rep = AnalyzerReport.objects.create(
            cortex_job_id="j3", type="url", status="Success", analyzer=self.analyzer,
            url=url, level="safe", confidence=90, score=0,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        rep.screenshot_bucket = "shots"
        rep.screenshot_key = f"report-{rep.id}.png"
        rep.save(update_fields=["screenshot_bucket", "screenshot_key"])

        img = _PNG + b"\x00" * (5 * 1024 * 1024 // 2 - len(_PNG))
        get_object = get_client.return_value.get_object
        get_object.return_value = MagicMock(read=lambda: img)
        body = self._get().content.decode()
        embedded = body.count("data:image/png;base64,")
        self.assertEqual(embedded, 2)
        # 2 embedded + 1 fetch that overshot the cap; the 4th row never fetches.
        self.assertEqual(get_object.call_count, 3)
        self.assertLess(get_object.call_count, 4)
        self.assertIn("Screenshot omitted from the report", body)

    @patch("api.views.case_report.get_s3_client")
    def test_fetch_failure_renders_omitted_note(self, get_client):
        get_client.return_value.get_object.side_effect = RuntimeError("minio down")
        body = self._get().content.decode()
        self.assertNotIn("data:image/png;base64,", body)
        self.assertIn("Screenshot omitted from the report", body)
