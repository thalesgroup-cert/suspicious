from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from case_handler.case_utils.case_creator import CaseCreator


class ReporterContextTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="rc_u", password="x")

    def test_default_blank(self):
        case = Case.objects.create(description="", reporter=self.user)
        self.assertEqual(case.reporter_context, "")

    def test_create_case_stores_reporter_context(self):
        case = CaseCreator(self.user).create_case(
            description="d", reporter_context="user said: looks like phishing"
        )
        case.refresh_from_db()
        self.assertEqual(case.reporter_context, "user said: looks like phishing")

    def test_finalise_does_not_overwrite_reporter_context(self):
        from cortex_job.cortex_utils.reconciliation import finalise
        case = CaseCreator(self.user).create_case(
            description="original", reporter_context="keep me"
        )
        with patch(
            "cortex_job.cortex_utils.reconciliation.CortexAnalyzerReports.get_report"
        ):
            finalise(case)
        case.refresh_from_db()
        self.assertEqual(case.reporter_context, "keep me")
        self.assertNotEqual(case.description, "original")
