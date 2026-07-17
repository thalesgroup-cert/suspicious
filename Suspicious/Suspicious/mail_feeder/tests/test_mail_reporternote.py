from django.test import TestCase
from mail_feeder.models import Mail


class MailReporterNoteTests(TestCase):
    def test_field_exists_and_defaults_empty(self):
        m = Mail._meta.get_field("reporterNote")
        self.assertTrue(m.blank)
        self.assertEqual(m.default, "")
