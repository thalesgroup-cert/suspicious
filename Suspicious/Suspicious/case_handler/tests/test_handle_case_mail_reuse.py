from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase

from case_handler.case_utils.case_creator import CaseCreator
from case_handler.case_utils.case_handler import CaseHandler
from case_handler.models import Case
from django.utils import timezone
from mail_feeder.models import Mail


class WebMailCaseReuseTests(TestCase):
    """A UI mail upload must yield one case, the one that holds the analyzers.

    Regression: the mail pipeline opened a case and launched every analyzer on
    it, then handle_case opened a second case for the same mail. The UI showed
    the second one: no jobs, finalised Safe in seconds, no AI score.
    """

    def setUp(self):
        self.feeder_user = User.objects.create(username="feeder@example.com")
        self.user = User.objects.create(username="analyst@example.com")
        self.mail = Mail.objects.create(subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m1")
        request = RequestFactory().post("/api/submit")
        request.user = self.user
        self.handler = CaseHandler(request, *[_Form() for _ in range(3)])

    def test_reuses_the_pipeline_case_for_the_same_mail(self):
        pipeline_case = CaseCreator(self.feeder_user).create_case(description="", mail_instance=self.mail)

        case = self.handler.handle_case(mail_inst=self.mail, external_ref="ref-1")

        self.assertEqual(case.pk, pipeline_case.pk)
        self.assertEqual(Case.objects.filter(fileOrMail__mail=self.mail).count(), 1)
        case.refresh_from_db()
        self.assertEqual(case.reporter, self.user)
        self.assertEqual(case.external_ref, "ref-1")

    def test_creates_a_case_when_the_pipeline_made_none(self):
        case = self.handler.handle_case(mail_inst=self.mail)

        self.assertEqual(Case.objects.filter(fileOrMail__mail=self.mail).count(), 1)
        self.assertEqual(case.reporter, self.user)


class _Form:
    def is_valid(self):
        return False
