from datetime import datetime, timezone as dt_tz

from django.contrib.auth.models import Group, User
from rest_framework.test import APITestCase

from dashboard.models import TotalCasesStats, UserCasesMonthlyStats


class HomeSummaryTests(APITestCase):
    URL = "/api/home/summary/?month=10&year=2026"

    def setUp(self):
        row = TotalCasesStats.objects.create(total_cases=182)
        # auto_now_add ignores create(); force the October 2026 date.
        TotalCasesStats.objects.filter(pk=row.pk).update(
            creation_date=datetime(2026, 10, 5, tzinfo=dt_tz.utc)
        )

    def _get(self, user):
        self.client.force_authenticate(user)
        return self.client.get(self.URL)

    def test_regular_user_sees_own_count(self):
        user = User.objects.create_user("u1", password="x")
        UserCasesMonthlyStats.objects.create(
            user=user, month="10", year="2026", total_cases=3, safe_cases=3
        )
        data = self._get(user).data
        self.assertEqual(data["monthly"]["user_items"], 3)
        self.assertEqual(data["monthly"]["everyone_items"], 182)
        self.assertIn("You have submitted 3 items", data["spotlight"]["description"])
        self.assertNotIn("182", data["spotlight"]["description"])

    def test_regular_user_without_stats(self):
        user = User.objects.create_user("u2", password="x")
        data = self._get(user).data
        self.assertEqual(data["monthly"]["user_items"], 0)
        self.assertEqual(
            data["spotlight"]["description"], "You have submitted 0 items this month."
        )

    def test_cert_spotlight_unchanged(self):
        user = User.objects.create_user("u3", password="x")
        user.groups.add(Group.objects.get_or_create(name="CERT")[0])
        data = self._get(user).data
        self.assertTrue(
            data["spotlight"]["description"].startswith(
                "There have been 182 submitted cases this month."
            )
        )

    def test_ciso_without_scope(self):
        user = User.objects.create_user("u4", password="x")
        user.groups.add(Group.objects.get_or_create(name="CISO")[0])
        data = self._get(user).data
        self.assertTrue(data["show_scope_modal"])
        self.assertIn("user_items", data["monthly"])
        self.assertEqual(
            data["spotlight"]["description"],
            "Choose your scope to see activity for it.",
        )
        self.assertEqual(data["spotlight"]["cta_path"], "/dashboard")

    def test_regular_user_singular(self):
        user = User.objects.create_user("u5", password="x")
        UserCasesMonthlyStats.objects.create(
            user=user, month="10", year="2026", total_cases=1, safe_cases=1
        )
        self.assertEqual(
            self._get(user).data["spotlight"]["description"],
            "You have submitted 1 item this month.",
        )
