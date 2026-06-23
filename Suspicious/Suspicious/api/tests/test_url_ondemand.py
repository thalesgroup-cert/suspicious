"""
Tests for POST /api/submissions/<id>/urls/<url_id>/analyze/ (Task 7).

Fixture construction follows the same pattern as test_url_planner_serialization.py:
  - nonFileIocs path: Case -> CaseHasNonFileIocs -> URL
  - mail path: Case -> CaseHasFileOrMail -> Mail -> MailArtifact -> ArtifactIsUrl -> URL

Authorization tests verify:
  - unauthenticated users get 401/403
  - non-owner gets 403 (CanAccessSubmission raises PermissionDenied)
  - url_id from a different submission gets 404 (Fix 1 binding)
  - owner with valid url gets 202 (dispatch mocked)
"""
from unittest import mock

from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

from case_handler.models import Case, CaseHasNonFileIocs, CaseHasFileOrMail
from mail_feeder.models import Mail, MailArtifact, ArtifactIsUrl
from url_process.models import URL

User = get_user_model()


def _make_user(username):
    return User.objects.create_user(username=username, password="pw-test")


def _make_url(address="https://evil.example.com/", status=URL.AnalysisStatus.SKIPPED):
    return URL.objects.create(address=address, analysis_status=status)


def _build_case_with_non_file_ioc(reporter, url):
    """Case -> CaseHasNonFileIocs -> URL (same bootstrapping as planner tests)."""
    case = Case.objects.create(reporter=reporter, description="test case")
    iocs = CaseHasNonFileIocs.objects.create(case=case, url=url)
    case.nonFileIocs = iocs
    case.save(update_fields=["nonFileIocs"])
    return case


def _build_case_with_mail_url(reporter, url):
    """Case -> CaseHasFileOrMail -> Mail -> MailArtifact -> ArtifactIsUrl -> URL."""
    mail = Mail.objects.create(
        subject="Test",
        reportedBy="sender@example.com",
        date="2026-01-01T00:00:00Z",
        to="recipient@example.com",
        mail_id="test-mail-id",
    )
    mail_artifact = MailArtifact.objects.create(mail=mail, artifact_type="URL")
    artifact_is_url = ArtifactIsUrl.objects.create(url=url, artifact=mail_artifact)
    mail_artifact.artifactIsUrl = artifact_is_url
    mail_artifact.save(update_fields=["artifactIsUrl"])

    case = Case.objects.create(reporter=reporter, description="mail case")
    file_or_mail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
    case.fileOrMail = file_or_mail
    case.save(update_fields=["fileOrMail"])
    return case


def _url(submission_id, url_id):
    return f"/api/submissions/{submission_id}/urls/{url_id}/analyze/"


class UrlOnDemandAuthTest(APITestCase):

    def setUp(self):
        self.owner = _make_user("owner")
        self.other = _make_user("other")
        self.url = _make_url()
        self.case = _build_case_with_non_file_ioc(self.owner, self.url)

    # ------------------------------------------------------------------
    # Fix 3a: unauthenticated → 401/403
    # ------------------------------------------------------------------
    def test_requires_auth(self):
        resp = self.client.post(_url(self.case.pk, self.url.pk))
        self.assertIn(resp.status_code, (401, 403))

    # ------------------------------------------------------------------
    # Fix 3b: authenticated non-owner → 403 (CanAccessSubmission)
    # ------------------------------------------------------------------
    def test_non_owner_forbidden(self):
        """User B POSTs against a case owned by user A → 403 from CanAccessSubmission."""
        self.client.force_authenticate(self.other)
        resp = self.client.post(_url(self.case.pk, self.url.pk))
        self.assertEqual(resp.status_code, 403)

    # ------------------------------------------------------------------
    # Fix 3c / Fix 1: url_id from a different case → 404
    # ------------------------------------------------------------------
    def test_url_from_other_submission_404(self):
        """
        Owner A has case1 (with url1) and case2 (with url2).
        Posting to /submissions/<case2>/urls/<url1>/analyze/ must return 404.
        """
        url2 = _make_url("https://other.example.com/")
        case2 = _build_case_with_non_file_ioc(self.owner, url2)

        self.client.force_authenticate(self.owner)
        # url1 (self.url) belongs to case1 (self.case), not case2
        resp = self.client.post(_url(case2.pk, self.url.pk))
        self.assertEqual(resp.status_code, 404)

    # ------------------------------------------------------------------
    # Fix 3d: owner with linked skipped url → 202
    # ------------------------------------------------------------------
    @mock.patch("api.views.url_analysis.CortexJob")
    def test_owner_can_queue(self, mock_cortex_cls):
        """Owner POSTs for their own linked skipped URL → 202 (Cortex mocked)."""
        mock_cortex_cls.return_value.launch_cortex_jobs.return_value = None
        self.client.force_authenticate(self.owner)
        resp = self.client.post(_url(self.case.pk, self.url.pk))
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(resp.data["status"], "queued")
        self.url.refresh_from_db()
        self.assertEqual(self.url.analysis_status, URL.AnalysisStatus.PENDING)

    # ------------------------------------------------------------------
    # Fix 3e: mail path — url linked via mail artifact is accessible
    # ------------------------------------------------------------------
    @mock.patch("api.views.url_analysis.CortexJob")
    def test_owner_can_queue_via_mail_path(self, mock_cortex_cls):
        """URL linked via Mail -> MailArtifact -> ArtifactIsUrl path is authorised."""
        mock_cortex_cls.return_value.launch_cortex_jobs.return_value = None
        mail_url = _make_url("https://mail-artifact.example.com/")
        mail_case = _build_case_with_mail_url(self.owner, mail_url)
        self.client.force_authenticate(self.owner)
        resp = self.client.post(_url(mail_case.pk, mail_url.pk))
        self.assertEqual(resp.status_code, 202)

    # ------------------------------------------------------------------
    # Rollback test (Fix 2): dispatch failure restores prior status
    # ------------------------------------------------------------------
    @mock.patch("api.views.url_analysis.CortexJob")
    def test_dispatch_failure_restores_status(self, mock_cortex_cls):
        """On 502, the URL's analysis_status must be restored to its pre-call value."""
        mock_cortex_cls.return_value.launch_cortex_jobs.side_effect = RuntimeError("boom")
        self.client.force_authenticate(self.owner)
        resp = self.client.post(_url(self.case.pk, self.url.pk))
        self.assertEqual(resp.status_code, 502)
        self.url.refresh_from_db()
        self.assertEqual(self.url.analysis_status, URL.AnalysisStatus.SKIPPED)
