"""
Case result update, persistence, and notification.
"""
import logging

from django.db import transaction

from dashboard.models import UserCasesMonthlyStats
from mail_feeder.models import MailInfo

logger              = logging.getLogger(__name__)
update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def update_case_results(case, reports, is_malicious, failure):
    """
    Derive and set case.results and case.analysis_done from scoring outputs.
    Does NOT call case.save() — the caller is responsible for persistence.
    """
    from score_process.scoring.case_score_calculation import calculate_result_ranges

    try:
        update_cases_logger.info("Deriving case results from final score %s.", case.final_score)
        case.results      = calculate_result_ranges(case.final_score)
        case.analysis_done = max(0, len(reports) - failure)

        # Override to Dangerous when at least one third of analyzers — and at
        # least one — flagged malicious. The `max(1, …)` floor prevents
        # `len(reports) // 3 == 0` from short-circuiting the comparison and
        # forcing every case (including 0-report and 0-malicious ones) into
        # Dangerous.
        threshold = max(1, len(reports) // 3)
        if is_malicious >= threshold:
            update_cases_logger.info(
                "Malicious report count (%s) >= threshold (%s) — forcing Dangerous.",
                is_malicious, threshold,
            )
            case.results = "Dangerous"

        if case.analysis_done == 0 and case.results != "Dangerous":
            update_cases_logger.warning(
                "Case %s: no analysis completed and result is not Dangerous.", case.id
            )

    except Exception as exc:
        update_cases_logger.error("Failed to update case results for %s: %s", case.id, exc)


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
    """Update KPI counters and per-user monthly stats for the given case."""
    try:
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

    except Exception as exc:
        update_cases_logger.error("Failed to update KPI/user stats: %s", exc)