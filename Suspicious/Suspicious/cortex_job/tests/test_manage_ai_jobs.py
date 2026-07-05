from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
from mail_feeder.models import Mail


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
        # Reached the archive lookup (past status + mail checks) — proves the
        # stale status guard is gone.
        self.assertIn("No archive file found", msgs)
        self.assertNotIn("Skipping AI job management", msgs)
