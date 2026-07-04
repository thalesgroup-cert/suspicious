from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case


class ResultDefaultTest(TestCase):
    def test_new_case_defaults_inconclusive(self):
        user = get_user_model().objects.create_user(username="rd_u", password="x")
        case = Case.objects.create(description="", reporter=user)
        self.assertEqual(case.results, "Inconclusive")
