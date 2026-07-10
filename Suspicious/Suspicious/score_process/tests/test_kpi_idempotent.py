from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from score_process.scoring.update_handler import update_kpi_and_user_stats


class KpiIdempotentTest(TestCase):
    def test_counts_once(self):
        user = get_user_model().objects.create_user(username="kpi_u", password="x")
        case = Case.objects.create(description="", reporter=user, results="Safe")
        update_kpi_and_user_stats(case)
        update_kpi_and_user_stats(case)
        case.refresh_from_db()
        self.assertTrue(case.kpi_counted)
        from tasp.cron.kpi import sync_monthly_kpi
        kpi = sync_monthly_kpi()
        self.assertEqual(kpi.total_cases_stats.total_cases, 1)
