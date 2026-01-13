from datetime import date
from dashboard.models import Kpi
from dashboard.dash_utils.dashboard import update_all_kpi_stats
import logging

logger = logging.getLogger("cron.kpi")


def sync_monthly_kpi() -> Kpi:
    today = date.today()
    month = today.strftime("%m")
    year = today.year

    kpi, _ = Kpi.objects.get_or_create(month=month, year=year)
    update_all_kpi_stats(kpi, month, year)
    kpi.save()
    logger.info("KPI updated for %s-%s", year, month)
    return kpi
