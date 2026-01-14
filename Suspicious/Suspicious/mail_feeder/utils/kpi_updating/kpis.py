import logging
from django.db import transaction
from dashboard.models import Kpi, MonthlyReporterStats, UserCasesMonthlyStats
from .utils import Period, safe_get_or_create

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

class KpiService:
    """
    Service class responsible for managing KPI and user statistics updates.
    """

    @staticmethod
    @transaction.atomic
    def update_kpi_stats(month: int, year: int) -> None:
        """
        Update the KPI statistics for a given month and year.
        """
        period = Period(month=month, year=year)
        from tasp.cron.kpi import sync_monthly_kpi
        kpi = sync_monthly_kpi()

        stats = kpi.monthly_reporter_stats

        if stats:
            stats.new_reporters += 1
            stats.total_reporters += 1
            stats.save()
        else:
            new_stats = MonthlyReporterStats.objects.create(new_reporters=1, total_reporters=1)
            kpi.monthly_reporter_stats = new_stats
            new_stats.save()

        kpi.save()
        logger.info(f"KPI stats updated for {period.month}/{period.year}")

    @staticmethod
    def create_monthly_user_stats(user: object, month: int, year: int) -> None:
        """
        Create or update monthly user statistics.
        """
        period = Period(month=month, year=year)
        instance, created = safe_get_or_create(
            UserCasesMonthlyStats, user=user, month=period.month, year=period.year
        )
        instance.save()

        if created:
            logger.info(f"Created new user stats for {user} ({period.month}/{period.year})")
        else:
            logger.debug(f"User stats already existed for {user} ({period.month}/{period.year})")
