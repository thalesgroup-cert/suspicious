from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from case_handler.models import Case


class BacktestTest(TestCase):
    def test_runs_read_only(self):
        user = get_user_model().objects.create_user(username="bt_u", password="x")
        case = Case.objects.create(description="", reporter=user, results="Suspicious")
        out = StringIO()
        call_command("backtest_scoring", stdout=out)
        case.refresh_from_db()
        self.assertEqual(case.results, "Suspicious")   # unchanged — read-only
        self.assertIn("old", out.getvalue().lower())    # header printed
