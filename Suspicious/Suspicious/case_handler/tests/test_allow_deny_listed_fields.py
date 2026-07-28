from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.case_utils.case_creator import CaseCreator
from case_handler.models import Result


class CaseCreatorAllowListedTest(TestCase):
    def test_allow_listed_case_sets_flag_and_reason(self):
        user = get_user_model().objects.create_user(username="al_u", password="x")
        case = CaseCreator(user).create_case(
            allow_listed=True, allow_reason="Domain 'example.com' is allow-listed."
        )
        self.assertIsNotNone(case)
        self.assertTrue(case.is_allowlisted)
        self.assertFalse(case.is_denylisted)
        self.assertEqual(case.list_reason, "Domain 'example.com' is allow-listed.")
        self.assertEqual(case.results, Result.ALLOW_LISTED)

    def test_non_allow_listed_case_leaves_flags_unset(self):
        user = get_user_model().objects.create_user(username="al_u2", password="x")
        case = CaseCreator(user).create_case(allow_listed=False, allow_reason="")
        self.assertIsNotNone(case)
        self.assertFalse(case.is_allowlisted)
        self.assertFalse(case.is_denylisted)
        self.assertEqual(case.list_reason, "")
