from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail
from mail_feeder.models import Mail
from score_process.scoring.cortex_analyzers.contrib.ai_mail import AiMailParser


class AttachCaseToAlertSetsThehiveIdTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="attach_u", password="x")
        mail = Mail.objects.create(subject="s", mail_from="a@b.test", date=timezone.now(), mail_id="mail-1")
        self.case = Case.objects.create(description="", reporter=self.user)
        fileormail = CaseHasFileOrMail.objects.create(case=self.case, mail=mail)
        self.case.fileOrMail = fileormail
        self.case.save(update_fields=["fileOrMail"])

    def test_sets_thehive_alert_id(self):
        parser = AiMailParser.__new__(AiMailParser)
        with patch(
            "score_process.scoring.cortex_analyzers.contrib.ai_mail.build_mail_zip_from_minio",
            return_value=(None, None),
        ), patch(
            "score_process.scoring.cortex_analyzers.contrib.ai_mail.fetch_mail_files_from_minio",
            return_value=(None, None, None, None),
        ):
            parser._attach_case_to_alert(
                self.case.id, "~alert-123", "alert", MagicMock(), "https://stub", "key", True,
            )

        self.case.refresh_from_db()
        self.assertEqual(self.case.thehive_alert_id, "~alert-123")
