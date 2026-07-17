from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from api.serializers.investigations import InvestigationDetailsSerializer


class InvestigationReporterContextTest(TestCase):
    def test_exposes_reporter_context(self):
        user = get_user_model().objects.create_user(username="irc", password="x")
        case = Case.objects.create(
            description="", reporter=user, reporter_context="please check this URL",
        )
        data = InvestigationDetailsSerializer(case).data
        self.assertEqual(data["reporter_context"], "please check this URL")
        self.assertEqual(data["reporter_note"], "")

    def test_reporter_note_from_mail(self):
        from mail_feeder.models import Mail
        from case_handler.models import CaseHasFileOrMail
        from django.utils import timezone
        user = get_user_model().objects.create_user(username="irc2", password="x")
        mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m1",
            reporterNote="forwarded phishing",
        )
        case = Case.objects.create(description="", reporter=user)
        fm = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.fileOrMail = fm
        case.save(update_fields=["fileOrMail"])
        data = InvestigationDetailsSerializer(case).data
        self.assertEqual(data["reporter_note"], "forwarded phishing")
