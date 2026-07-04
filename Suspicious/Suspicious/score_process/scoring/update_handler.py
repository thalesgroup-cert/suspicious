"""
Case result update, persistence, and notification.
"""
import logging

from django.db import transaction

from dashboard.models import UserCasesMonthlyStats
from mail_feeder.models import MailInfo

logger              = logging.getLogger(__name__)
update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def save_case_results(case, mail):
    """
    Persist case and MailInfo.

    Reporter notification is handled by SmtpNotifyConnector via the
    ``case_finalised`` event — it is no longer sent inline here.
    """
    # ── 1. Persist MailInfo ──────────────────────────────────────────────
    try:
        mail_info              = MailInfo.objects.get(mail=mail)
        mail_info.is_analyzed  = True
        mail_info.is_dangerous = case.results == "Dangerous"
        mail_info.save(update_fields=["is_analyzed", "is_dangerous"])
    except MailInfo.DoesNotExist:
        update_cases_logger.error("MailInfo not found for mail %r — cannot save results.", mail)
        return

    # ── 2. Persist Case ──────────────────────────────────────────────────
    try:
        with transaction.atomic():
            case.save()
            update_cases_logger.info("Case %s and MailInfo saved.", case.id)
    except Exception as exc:
        update_cases_logger.error("Failed to save case %s: %s", case.id, exc)


def update_kpi_and_user_stats(case):
    """Update KPI counters and per-user monthly stats — exactly once per case.

    A row-level lock on the Case plus the ``kpi_counted`` flag make this a
    no-op on any re-finalisation (cron fallback, challenge→resolve), so a case
    can never be double-counted.
    """
    from case_handler.models import Case
    try:
        with transaction.atomic():
            locked = Case.objects.select_for_update().get(pk=case.pk)
            if locked.kpi_counted:
                return

            from tasp.cron.kpi import sync_monthly_kpi
            kpi = sync_monthly_kpi()

            kpi.monthly_cases_summary.update_case_results(case.results)
            kpi.monthly_cases_summary.update_case_results(case.category_ai)
            kpi.monthly_cases_summary.save()

            kpi.total_cases_stats.total_cases += 1
            kpi.total_cases_stats.save()

            stats = UserCasesMonthlyStats.objects.filter(
                user=case.reporter, month=kpi.month, year=kpi.year
            ).first()
            if not stats:
                stats = UserCasesMonthlyStats(user=case.reporter, month=kpi.month, year=kpi.year)

            stats.update_case_results(case.results)
            stats.update_case_results(case.category_ai)
            stats.total_cases += 1
            stats.save()

            locked.kpi_counted = True
            locked.save(update_fields=["kpi_counted"])
            case.kpi_counted = True

    except Exception as exc:
        update_cases_logger.error("Failed to update KPI/user stats: %s", exc)