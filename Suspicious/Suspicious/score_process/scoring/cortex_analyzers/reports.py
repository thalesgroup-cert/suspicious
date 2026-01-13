import json
import logging
from django.db.models import Max

from .service import CortexAnalyzerService
from cortex_job.models import AnalyzerReport
from score_process.scoring.processing import (
    process_file_ioc,
    process_mail,
    process_ioc,
)
from score_process.scoring.case_score_calculation import calculate_final_scores

from score_process.scoring.case_update import (
    update_case_results,
    save_case_results,
    update_kpi_and_user_stats,
)
from score_process.misp.service import MISPService
update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

from .utils import dump_model

class CortexAnalyzerReports:
    """
    Handles persistence and lifecycle of analyzer reports.
    """

    @staticmethod
    def process_analyzer_reports(
        reports,
        analyzer_reports,
        artifact_value,
        case_id,
    ):
        """
        Processes analyzer job outputs coming from Cortex.
        """
        failure_count = 0

        update_cases_logger.info(
            "[reports] Processing %d analyzer reports", len(analyzer_reports)
        )

        for report in analyzer_reports:
            try:
                if report.status == "Success":
                    CortexAnalyzerReports.create_and_save_report(
                        report,
                        artifact_value,
                        case_id,
                    )
                elif report.status == "Failure":
                    failure_count += CortexAnalyzerReports.handle_failure(report)

                update_cases_logger.info(
                    "Processed report id=%s status=%s score=%s confidence=%s",
                    report.id,
                    report.status,
                    report.score,
                    report.confidence,
                )

                reports.append(report)

            except Exception as exc:
                update_cases_logger.error(
                    "Error processing analyzer report: %s",
                    exc,
                    exc_info=True,
                )

        return failure_count

    @staticmethod
    def create_and_save_report(report, artifact_value, case_id):
        """
        Creates AnalyzerResult via AnalyzerFactory and updates AnalyzerReport.
        """
        try:
            update_cases_logger.info(
                "Creating analyzer result for artifact=%s analyzer=%s",
                artifact_value,
                report.analyzer.name,
            )

            result = CortexAnalyzerService.create_report(
                summary=report.report_summary,
                full=report.report_full,
                analyzer_name=report.analyzer.name,
                data=artifact_value,
                data_type=report.type,
                case_id=case_id,
            )

            result_dict = dump_model(result)
            category = result_dict.get("category", "Unknown")
            if isinstance(category, list):
                category = ", ".join(category)

            report.score = result_dict.get("score", 0)
            report.confidence = result_dict.get("confidence", 0)
            report.category = category
            report.level = result_dict.get("level", "info")
            report.details = result_dict.get("details", {})

            report.save()

        except Exception as exc:
            update_cases_logger.error(
                "Error saving analyzer report: %s",
                exc,
                exc_info=True,
            )

    @staticmethod
    def handle_failure(report):
        """
        Handles failed analyzer executions.
        """
        report.score = 5
        report.confidence = 0
        report.category = "Failed task"
        report.level = "info"
        report.details = {}
        report.save()
        return 1

    @staticmethod
    def get_analyzer_reports_by_type_and_artifact(artifact_type, artifact):
        """
        Returns latest analyzer reports per analyzer for a given artifact.
        """
        field_mapping = {
            "file": "file",
            "hash": "hash",
            "url": "url",
            "ip": "ip",
            "mail_body": "mail_body",
            "mail_header": "mail_header",
        }

        field_name = field_mapping.get(artifact_type)
        if not field_name:
            return None

        latest_ids = (
            AnalyzerReport.objects
            .filter(**{field_name: artifact})
            .values("analyzer_id")
            .annotate(latest_id=Max("id"))
        )

        return AnalyzerReport.objects.filter(
            id__in=[row["latest_id"] for row in latest_ids]
        )


    @staticmethod
    def get_report(case):
        """
        Generates a report for the given case.

        Args:
            case: The case object for which the report is generated.

        Returns:
            None
        """
        from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
        if not case:
            update_cases_logger.warning("[score_check.py] get_report: Case does not exist.")
            return
        cortex_job_manager = CortexJobManager()
        reports = []
        total_scores = []
        total_confidences = []
        is_malicious = 0
        failure = 0
        mail = None

        try:
            # Process file or mail
            if case.fileOrMail:
                file = getattr(case.fileOrMail, 'file', None)
                if file:
                    update_cases_logger.info(f"[score_check.py] get_report: Processing file {file}")
                    failure += process_file_ioc(file, reports, total_scores, total_confidences, is_malicious, case.id)

                mail = getattr(case.fileOrMail, 'mail', None)
                if mail:
                    update_cases_logger.info(f"[score_check.py] get_report: Processing mail: {mail.subject}")
                    failure += process_mail(mail, reports, total_scores, total_confidences, is_malicious, case.id)
                    cortex_job_manager.manage_ai_jobs(case)
            # Process IOCs
            if case.nonFileIocs:
                ioc_data = case.nonFileIocs.get_iocs()
                for ioc_type in ["url", "ip", "hash", "domain"]:
                    ioc = ioc_data.get(ioc_type)
                    if ioc:
                        update_cases_logger.info(f"[score_check.py] get_report: Processing {ioc_type}: {ioc}")
                        failure += process_ioc(ioc, ioc_type, reports, total_scores, total_confidences, is_malicious)


            # Compute final scores
            calculate_final_scores(total_scores, total_confidences, case)

            # Update case with results
            update_case_results(case, reports, is_malicious, failure)
            save_case_results(case, mail)
            update_kpi_and_user_stats(case)

            # Update MISP
            misp_handler = MISPService(primary=True)
            misp_handler.update_misp(case)

            update_cases_logger.info("[score_check.py] get_report: Case report successfully saved.")

        except Exception as e:
            update_cases_logger.error(f"[score_check.py] get_report: Error processing case: {e}", exc_info=True)
