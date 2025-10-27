import logging
from django.utils import timezone
from datetime import timedelta
from cortex_job.models import AnalyzerReport

logger = logging.getLogger("cron.cleanup")


def delete_old_analyzer_reports(days: int = 30) -> None:
    """Supprime les AnalyzerReport plus vieux que `days` jours."""
    cutoff = timezone.now() - timedelta(days=days)
    try:
        AnalyzerReport.objects.filter(creation_date__lt=cutoff).delete()
    except Exception:
        logger.exception("Failed to delete old analyzer reports")

# placeholder pour suppression de jobs cortex (commentée car asynchrone / volumineuse)
# def delete_old_cortex_jobs(...):
#     pass
