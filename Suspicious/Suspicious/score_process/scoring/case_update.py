import logging
from django.db import transaction
from dashboard.models import Kpi, MonthlyCasesSummary, TotalCasesStats, UserCasesMonthlyStats
from mail_feeder.models import MailInfo
from score_process.score_utils.send_mail.service import MailNotificationService

logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')

def update_case_results(case, reports, is_malicious, failure):
    """
    Updates the analysis results of a case using scoring logic and detected threats.

    Args:
        case (Case): The case object to update.
        reports (list): List of reports tied to the case.
        is_malicious (int): Count of reports flagged as malicious.
        failure (int): Count of failed report processes.
    """
    from score_process.scoring.case_score_calculation import calculate_result_ranges

    try:
        update_cases_logger.info("Updating case results based on scoring...")
        case.results = calculate_result_ranges(case.finalScore)

        if is_malicious >= len(reports) / 3:
            case.results = "Dangerous"

        case.analysis_done = max(0, len(reports) - failure)

        if case.analysis_done == 0 and case.results != "Dangerous":
            update_cases_logger.warning("No analysis completed, case might be invalid.")

    except Exception as e:
        update_cases_logger.error(f"Failed to update case results: {str(e)}")

def save_case_results(case, mail):
    """
    Saves the updated case and associated mail information. Sends final report mail to user.

    Args:
        case (Case): The case object.
        mail (MailInfo): The related mail entry.
    """
    try:
        mail_info = MailInfo.objects.get(mail=mail)
        mail_info.is_analyzed = True
        mail_info.is_dangerous = case.results == "Dangerous"
        mail_info.save()
        cls = MailNotificationService.from_settings()
        cls.send_final(mail_info, case)

    except MailInfo.DoesNotExist:
        update_cases_logger.error("MailInfo entry not found for provided mail object.")
        return

    try:
        with transaction.atomic():
            case.save()
            update_cases_logger.info("Case and MailInfo saved successfully.")
    except Exception as e:
        update_cases_logger.error(f"Failed to save case results: {str(e)}")

def update_kpi_and_user_stats(case):
    """
    Updates KPI and user statistics for the given case.

    Args:
        case (Case): The case from which to derive stats.
    """
    try:
        from tasp.cron.kpi import sync_monthly_kpi
        kpi = sync_monthly_kpi()

        # Update monthly summary
        kpi.monthly_cases_summary.update_case_results(case.results)
        kpi.monthly_cases_summary.update_case_results(case.categoryAI)
        kpi.monthly_cases_summary.save()

        # Update global case count
        kpi.total_cases_stats.total_cases += 1
        kpi.total_cases_stats.save()

        # Update per-user monthly stats
        stats = UserCasesMonthlyStats.objects.filter(
            user=case.reporter, month=kpi.month, year=kpi.year
        ).first()
        if not stats:
            stats = UserCasesMonthlyStats(
                user=case.reporter, month=kpi.month, year=kpi.year
            )
        stats.update_case_results(case.results)
        stats.update_case_results(case.categoryAI)
        stats.total_cases += 1
        stats.save()

    except Exception as e:
        update_cases_logger.error(f"Failed to update KPI/user stats: {str(e)}")
