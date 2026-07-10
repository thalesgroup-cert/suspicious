"""
Tests for the url_artifacts field added to SubmissionDetailsSerializer (Task 6).

The url_artifacts field must list ALL URL objects linked to a case —
including skipped ones that have zero AnalyzerReport rows — so the UI
can offer an on-demand "Analyze" button for every URL.

Two construction paths are exercised:
  1. nonFileIocs -> CaseHasNonFileIocs -> URL  (simplest graph, used for skipped/analyzed)
  2. fileOrMail -> Mail -> MailArtifact -> ArtifactIsUrl -> URL  (mail path, used for reused)

The test for a reused URL asserts that analyzed_url_id is forwarded correctly.

Note on circular FKs: both Case->CaseHasFileOrMail and CaseHasFileOrMail->Case
are non-nullable, so we must:
  1. Create Case with the association FK = None (null=True on Case.fileOrMail).
  2. Create CaseHasFileOrMail / CaseHasNonFileIocs with case=the_case.
  3. Update Case.fileOrMail / Case.nonFileIocs and save.
Same pattern applies to the nonFileIocs path.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, CaseHasNonFileIocs, CaseHasFileOrMail
from mail_feeder.models import Mail, MailArtifact, ArtifactIsUrl
from url_process.models import URL

from api.serializers.submissions import SubmissionDetailsSerializer

User = get_user_model()


def _make_user(username):
    return User.objects.create_user(username=username, password="pw-test")


def _make_mail():
    """Create a minimal Mail row."""
    return Mail.objects.create(
        subject="Test mail",
        reportedBy="sender@example.com",
        date="2026-01-01T00:00:00Z",
        to="recipient@example.com",
        mail_id="test-mail-id",
    )


def _build_mail_with_url(url):
    """
    Create Mail -> MailArtifact <-> ArtifactIsUrl -> URL.
    ArtifactIsUrl.artifact FK is non-nullable so we create MailArtifact first,
    then ArtifactIsUrl referencing it, then back-fill MailArtifact.artifactIsUrl.
    """
    mail = _make_mail()
    mail_artifact = MailArtifact.objects.create(mail=mail, artifact_type="URL")
    artifact_is_url = ArtifactIsUrl.objects.create(url=url, artifact=mail_artifact)
    mail_artifact.artifactIsUrl = artifact_is_url
    mail_artifact.save(update_fields=["artifactIsUrl"])
    return mail


def _build_case_with_non_file_ioc(reporter, url):
    """
    Build Case -> CaseHasNonFileIocs -> URL.
    Both Case.nonFileIocs FK and CaseHasNonFileIocs.case FK are non-nullable
    but Case.nonFileIocs is nullable (null=True, blank=True), so we:
      1. Create Case without nonFileIocs.
      2. Create CaseHasNonFileIocs with case=case.
      3. Assign back and save.
    """
    case = Case.objects.create(reporter=reporter, description="test case")
    iocs = CaseHasNonFileIocs.objects.create(case=case, url=url)
    case.nonFileIocs = iocs
    case.save(update_fields=["nonFileIocs"])
    return case


def _build_case_with_mail(reporter, mail):
    """
    Build Case -> CaseHasFileOrMail -> Mail.
    Same bootstrapping pattern as _build_case_with_non_file_ioc.
    """
    case = Case.objects.create(reporter=reporter, description="mail case")
    file_or_mail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
    case.fileOrMail = file_or_mail
    case.save(update_fields=["fileOrMail"])
    return case


def _select_case_with_prefetch(pk):
    """Re-fetch case with same select_related/prefetch_related the view uses."""
    return (
        Case.objects.select_related(
            "fileOrMail", "fileOrMail__mail",
            "nonFileIocs", "nonFileIocs__url",
        )
        .prefetch_related(
            "fileOrMail__mail__mail_artifacts",
            "fileOrMail__mail__mail_artifacts__artifactIsUrl",
            "fileOrMail__mail__mail_artifacts__artifactIsUrl__url",
        )
        .get(pk=pk)
    )


class UrlArtifactsViaIocPathTest(TestCase):
    """
    Simplest path: Case -> CaseHasNonFileIocs -> URL.
    Verifies that a skipped URL and an analyzed URL both appear in url_artifacts.
    """

    def setUp(self):
        self.reporter = _make_user("ioc_reporter")

        self.url_skipped = URL.objects.create(
            address="https://evil.example.com/skipped",
            analysis_status=URL.AnalysisStatus.SKIPPED,
            interestingness=3,
            canonical_key="evil.example.com/skipped",
        )
        self.url_analyzed = URL.objects.create(
            address="https://good.example.com/analyzed",
            analysis_status=URL.AnalysisStatus.ANALYZED,
            interestingness=1,
            canonical_key="good.example.com/analyzed",
        )

    def _serialize(self, case):
        case = _select_case_with_prefetch(case.pk)
        serializer = SubmissionDetailsSerializer(case, context={"analyzer_reports": []})
        return serializer.data["url_artifacts"]

    def test_skipped_url_appears_in_url_artifacts(self):
        """A URL with status=skipped must appear in url_artifacts even with zero AnalyzerReports."""
        case = _build_case_with_non_file_ioc(self.reporter, self.url_skipped)
        artifacts = self._serialize(case)
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art["id"], self.url_skipped.pk)
        self.assertEqual(art["address"], "https://evil.example.com/skipped")
        self.assertEqual(art["analysis_status"], "skipped")
        self.assertEqual(art["interestingness"], 3)
        self.assertEqual(art["canonical_key"], "evil.example.com/skipped")
        self.assertIsNone(art["analyzed_url_id"])

    def test_analyzed_url_appears_in_url_artifacts(self):
        case = _build_case_with_non_file_ioc(self.reporter, self.url_analyzed)
        artifacts = self._serialize(case)
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art["id"], self.url_analyzed.pk)
        self.assertEqual(art["analysis_status"], "analyzed")


class UrlArtifactsViaMailPathTest(TestCase):
    """
    Mail artifact path: Case -> CaseHasFileOrMail -> Mail -> MailArtifact -> ArtifactIsUrl -> URL.
    Verifies that a reused URL carries the correct analyzed_url_id.
    """

    def setUp(self):
        self.reporter = _make_user("mail_reporter")

        self.url_canonical = URL.objects.create(
            address="https://phish.example.com/canonical",
            analysis_status=URL.AnalysisStatus.ANALYZED,
        )
        self.url_reused = URL.objects.create(
            address="https://phish.example.com/reused",
            analysis_status=URL.AnalysisStatus.REUSED,
            analyzed_url=self.url_canonical,
        )

    def _serialize(self, case):
        case = _select_case_with_prefetch(case.pk)
        serializer = SubmissionDetailsSerializer(case, context={"analyzer_reports": []})
        return serializer.data["url_artifacts"]

    def test_reused_url_carries_analyzed_url_id(self):
        mail = _build_mail_with_url(self.url_reused)
        case = _build_case_with_mail(self.reporter, mail)
        artifacts = self._serialize(case)
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art["id"], self.url_reused.pk)
        self.assertEqual(art["analysis_status"], "reused")
        self.assertEqual(art["analyzed_url_id"], self.url_canonical.pk)

    def test_mail_path_url_appears_in_url_artifacts(self):
        mail = _build_mail_with_url(self.url_canonical)
        case = _build_case_with_mail(self.reporter, mail)
        artifacts = self._serialize(case)
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art["id"], self.url_canonical.pk)
        self.assertEqual(art["analysis_status"], "analyzed")
        self.assertIsNone(art["analyzed_url_id"])


class UrlArtifactsDeduplicationTest(TestCase):
    """
    A URL referenced by BOTH paths (nonFileIocs and a mail artifact) must
    appear only once in url_artifacts.
    """

    def setUp(self):
        self.reporter = _make_user("dedup_reporter")
        self.url = URL.objects.create(
            address="https://dup.example.com/",
            analysis_status=URL.AnalysisStatus.ANALYZED,
        )

    def test_deduplication_across_paths(self):
        mail = _build_mail_with_url(self.url)
        case = Case.objects.create(reporter=self.reporter, description="dup case")
        file_or_mail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        iocs = CaseHasNonFileIocs.objects.create(case=case, url=self.url)
        case.fileOrMail = file_or_mail
        case.nonFileIocs = iocs
        case.save(update_fields=["fileOrMail", "nonFileIocs"])

        case = _select_case_with_prefetch(case.pk)
        serializer = SubmissionDetailsSerializer(case, context={"analyzer_reports": []})
        artifacts = serializer.data["url_artifacts"]
        ids = [a["id"] for a in artifacts]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate URL ids in url_artifacts")
        self.assertIn(self.url.pk, ids)
