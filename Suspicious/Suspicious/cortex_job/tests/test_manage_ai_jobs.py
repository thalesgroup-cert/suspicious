from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from file_process.models import File
from hash_process.models import Hash
from mail_feeder.models import Mail, MailArchive


class ManageAiJobsStatusGuardTest(TestCase):
    """Regression: get_report (hence manage_ai_jobs) now runs during the SCORING
    state, whose display status is "On Going" — never "Done". manage_ai_jobs must
    still process AI, so it must NOT early-return on status. Old code bailed on
    `status != "Done"`, silently skipping AI classification for every mail case.
    """

    def test_proceeds_past_status_when_not_done(self):
        user = get_user_model().objects.create_user(username="ai_u", password="x")
        mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m1"
        )
        case = Case.objects.create(description="", reporter=user, status="On Going")
        fm = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.fileOrMail = fm
        case.save(update_fields=["fileOrMail"])

        logger_name = "tasp.cron.update_ongoing_case_jobs"
        with self.assertLogs(logger_name, level="INFO") as cm:
            CortexJobManager().manage_ai_jobs(case)
        msgs = "\n".join(cm.output)
        self.assertIn("No archive file found", msgs)
        self.assertNotIn("Skipping AI job management", msgs)


class ManageAiJobsCategoryLengthTest(TestCase):
    """Regression: Case.category_ai is CharField(max_length=20), but
    get_sub_class() writes an external Cortex analyzer's freeform
    sub_classification string into it with no length guard. Confirmed in
    production (case 306, analyzer AI_Mail_Analyzer_2_0 — a version not
    present in this repo) as a MySQL 1406 "Data too long" DataError, which
    silently aborts the whole case.save() and drops score_ai/confidence_ai
    too, even though those fields were valid. Since the project's test
    database is SQLite (no column-length enforcement at the storage layer),
    this test asserts the application-level guard directly rather than
    relying on a DB exception: category_ai must never exceed max_length.
    """

    def setUp(self):
        from settings.config import get_section

        user = get_user_model().objects.create_user(username="ai_len_u", password="x")
        mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m-len"
        )
        case = Case.objects.create(description="", reporter=user, status="On Going")
        fm = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.fileOrMail = fm
        case.save(update_fields=["fileOrMail"])
        self.case = case

        hash_obj = Hash.objects.create(value="deadbeef")
        file_obj = File.objects.create(linked_hash=hash_obj, tmp_path="x.tar.gz")
        MailArchive.objects.create(mail=mail, archive=file_obj)

        ai_name = get_section("integrations.cortex").get("analyzers", {}).get("ai")
        analyzer = Analyzer.objects.create(analyzer_cortex_id="ai-len-1", name=ai_name, weight=0.2)
        AnalyzerReport.objects.create(
            cortex_job_id="job-ai-len",
            type="file",
            status="Success",
            analyzer=analyzer,
            file=file_obj,
            level="dangerous",
            confidence=99,
            score=10,
            report_summary={},
            report_full={"sub_classification": "A_Very_Long_Classification_Label_That_Overflows_Twenty"},
            report_taxonomy={},
        )

    def test_oversized_sub_classification_is_bounded_to_field_max_length(self):
        CortexJobManager().manage_ai_jobs(self.case)

        self.case.refresh_from_db()
        max_length = Case._meta.get_field("category_ai").max_length
        self.assertLessEqual(len(self.case.category_ai), max_length)


class ManageAiJobsNoReportYetTest(TestCase):
    """Regression: a MailArchive with no AnalyzerReport for the AI analyzer
    yet (analysis genuinely still pending, or the AI analyzer was never
    dispatched) is a normal, common state — NOT an error. The
    AnalyzerReport.DoesNotExist handler referenced an `analyzer` variable
    that only the *successful* .get() above it would have bound, so this
    path raised UnboundLocalError every time instead of running its own
    (already-written, otherwise-correct) fallback logic. Because
    manage_ai_jobs is invoked from get_report() before collect_signals /
    score_case / apply_verdict, that crash silently skipped verdict
    computation for every mail case reaching this state, leaving
    Case.results at its default Inconclusive regardless of the real
    analyzer findings.
    """

    def setUp(self):
        user = get_user_model().objects.create_user(username="ai_pending_u", password="x")
        mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m-pending"
        )
        self.case = Case.objects.create(description="", reporter=user, status="On Going")
        fm = CaseHasFileOrMail.objects.create(case=self.case, mail=mail)
        self.case.fileOrMail = fm
        self.case.save(update_fields=["fileOrMail"])

        hash_obj = Hash.objects.create(value="pendinghash")
        self.file_obj = File.objects.create(linked_hash=hash_obj, tmp_path="pending.tar.gz")
        MailArchive.objects.create(mail=mail, archive=self.file_obj)

    def test_no_report_yet_and_no_dispatched_job_marks_inconclusive(self):
        # No CaseAnalyzerJob for the AI analyzer either -> "never dispatched".
        CortexJobManager().manage_ai_jobs(self.case)  # must not raise

        self.case.refresh_from_db()
        self.assertEqual(self.case.results_ai, "Inconclusive")

    def test_no_report_yet_but_job_still_running_does_not_mark_inconclusive(self):
        from settings.config import get_section

        ai_name = get_section("integrations.cortex").get("analyzers", {}).get("ai")
        analyzer = Analyzer.objects.create(analyzer_cortex_id="ai-pending-1", name=ai_name, weight=0.2)
        CaseAnalyzerJob.objects.create(
            case=self.case, cortex_job_id="job-ai-pending",
            analyzer=analyzer, status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )

        CortexJobManager().manage_ai_jobs(self.case)  # must not raise

        self.case.refresh_from_db()
        # results_ai is untouched (default) while the job is still running.
        self.assertEqual(self.case.results_ai, "Suspicious")
