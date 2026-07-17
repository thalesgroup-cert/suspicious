from datetime import timedelta

from celery.utils.log import get_task_logger
from django.utils import timezone

logger = get_task_logger(__name__)


def materialise_dashboard_snapshots() -> None:
    """Pre-compute and persist DashboardSnapshot rows for current + previous month.

    Previous month is included only during the first 3 days of a new month,
    when its data may still be finalised by late-arriving cases.
    """
    from dashboard.snapshot import materialise_snapshot

    now = timezone.now()
    months = [(now.month, now.year)]

    if now.day <= 3:
        prev = (now.replace(day=1) - timedelta(days=1))
        months.append((prev.month, prev.year))

    for month, year in months:
        try:
            materialise_snapshot(month=month, year=year)
            logger.info("Dashboard snapshot materialised for %d-%02d", year, month)
        except Exception:
            logger.exception("Failed to materialise dashboard snapshot for %d-%02d", year, month)
