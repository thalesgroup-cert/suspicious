from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case


class VerdictExplanationFieldTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="test_user", password="pass")

    def test_defaults_none(self):
        c = Case.objects.create(description="", reporter=self.user)
        c.refresh_from_db()
        self.assertIsNone(c.verdict_explanation)

    def test_stores_dict(self):
        c = Case.objects.create(
            description="",
            reporter=self.user,
            verdict_explanation={"band": "Safe", "sources": []},
        )
        c.refresh_from_db()
        self.assertEqual(c.verdict_explanation["band"], "Safe")
