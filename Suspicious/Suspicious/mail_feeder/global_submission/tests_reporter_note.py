# Suspicious/Suspicious/mail_feeder/global_submission/tests_reporter_note.py
from django.test import TestCase
from mail_feeder.global_submission.models import MailSubmissionData


class ReporterNoteFieldTests(TestCase):
    def test_submission_data_has_reporter_note(self):
        s = MailSubmissionData(
            workdir="/tmp", filename="m.eml", email_id="x", user="u@x",
            bucket_name="b", is_submitted=False, reporter_note="please check",
        )
        self.assertEqual(s.reporter_note, "please check")
