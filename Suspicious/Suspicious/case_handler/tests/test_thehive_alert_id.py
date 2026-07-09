from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case


class CaseThehiveAlertIdTest(TestCase):
    def test_default_blank(self):
        user = get_user_model().objects.create_user(username="thai_u", password="x")
        case = Case.objects.create(description="", reporter=user)
        self.assertEqual(case.thehive_alert_id, "")

    def test_stores_alert_id(self):
        user = get_user_model().objects.create_user(username="thai_u2", password="x")
        case = Case.objects.create(description="", reporter=user, thehive_alert_id="~123456")
        case.refresh_from_db()
        self.assertEqual(case.thehive_alert_id, "~123456")
