from django.test import TestCase

from mail_feeder.models import Mail
from mail_feeder.utils.define_email.email import EmailService


def _data(**over):
    base = {
        "reportedSubject": "hello",
        "reportedBy": "jordan.kim@meridian.example",
        "to": "suspicious@meridian.example",
        "date": "Tue, 06 Oct 2026 14:55:00 +0000",
        "id": "<abc@x>",
        "mail_from": "bad@evil.example",
    }
    base.update(over)
    return base


class OverLengthFieldsTest(TestCase):
    """A reported mail must never be dropped because a header is longer than
    the column; long subjects are an evasion trick, not a validation error."""

    def test_long_subject_is_truncated_not_rejected(self):
        res = EmailService().create_mail_instance(_data(reportedSubject="Newsletter " * 40))
        self.assertTrue(res.success, res.error)
        subject = Mail.objects.get(id=res.mail_id).subject
        self.assertEqual(len(subject), 255)
        self.assertTrue(subject.endswith("…"))
        self.assertTrue(subject.startswith("Newsletter Newsletter"))

    def test_long_recipient_list_is_truncated_not_rejected(self):
        to = ", ".join(f"user{i}@meridian.example" for i in range(40))
        res = EmailService().create_mail_instance(_data(to=to, cc=to, mail_from="x" * 400))
        self.assertTrue(res.success, res.error)
        mail = Mail.objects.get(id=res.mail_id)
        self.assertEqual((len(mail.to), len(mail.cc), len(mail.mail_from)), (255, 255, 255))

    def test_short_values_are_untouched(self):
        res = EmailService().create_mail_instance(_data())
        self.assertEqual(Mail.objects.get(id=res.mail_id).subject, "hello")
