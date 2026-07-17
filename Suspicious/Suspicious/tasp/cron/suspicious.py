import logging

from case_handler.models import Case

logger = logging.getLogger("tasp.cron.suspicious")


def check_challengeable():
    """
    Check if cases are challengeable and update their status accordingly.
    """
    cases = Case.objects.filter(is_challengeable=True)
    for case in cases:
        if not case.was_published_recently():
            case.is_challengeable = False
            case.save(update_fields=["is_challengeable"])