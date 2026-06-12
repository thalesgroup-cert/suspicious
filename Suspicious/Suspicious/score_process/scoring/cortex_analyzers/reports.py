# score_process/scoring/cortex_analyzers/reports.py
"""
Analyzer report lifecycle: execution, persistence, and querying.
"""
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
from score_process.scoring.update_handler import (
    update_case_results,
    save_case_results,
    update_kpi_and_user_stats,
)
from .utils import dump_model

update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

# Threshold above which a report is counted as "malicious" for the
# update_case_results majority-vote check.
MALICIOUS_SCORE_THRESHOLD = 8


class CortexAnalyzerReports:
    """Handles persistence and lifecycle of analyzer reports."""

    # ── public pipeline entry point ───────────────────────────────────────

    @staticmethod
    def get_report(case) -> None:
        """
        Score a case end-to-end: run analyzers, compute final scores,
        persist results, send notification email, update KPIs.
        """
        from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager

        if not case:
            update_cases_logger.warning("get_report called with no case.")
            return

        cortex_job_manager = CortexJobManager()
        reports:           list = []
        total_scores:      list = []
        total_confidences: list = []
        is_malicious:      int  = 0
        failure:           int  = 0
        mail               = None

        try:
            if case.fileOrMail:
                file = getattr(case.fileOrMail, "file", None)
                if file:
                    update_cases_logger.info("get_report: processing file for case %s.", case.id)
                    failure += process_file_ioc(
                        file, reports, total_scores, total_confidences,
                        is_malicious, case.id,
                    )

                mail = getattr(case.fileOrMail, "mail", None)
                if mail:
                    update_cases_logger.info(
                        "get_report: processing mail (subject=%r) for case %s.",
                        getattr(mail, "subject", ""), case.id,
                    )
                    failure += process_mail(
                        mail, reports, total_scores, total_confidences,
                        is_malicious, case.id,
                    )
                    cortex_job_manager.manage_ai_jobs(case)

            if case.nonFileIocs:
                ioc_data = case.nonFileIocs.get_iocs()
                for ioc_type in ("url", "ip", "hash", "domain"):
                    ioc = ioc_data.get(ioc_type)
                    if ioc:
                        update_cases_logger.info(
                            "get_report: processing %s IOC for case %s.", ioc_type, case.id
                        )
                        failure += process_ioc(
                            ioc, ioc_type, reports, total_scores, total_confidences,
                            is_malicious,
                        )

            # Count malicious reports for the majority-vote override in
            # update_case_results.  A report is "malicious" when the analyzer
            # assigned level=malicious or a score at or above the threshold.
            is_malicious = sum(
                1 for r in reports
                if getattr(r, "level", "") in ("malicious", "dangerous")
                or getattr(r, "score", 0) >= MALICIOUS_SCORE_THRESHOLD
            )
            update_cases_logger.info(
                "get_report: case %s — %d/%d reports malicious.",
                case.id, is_malicious, len(reports),
            )

            calculate_final_scores(total_scores, total_confidences, case)
            update_case_results(case, reports, is_malicious, failure)
            # mail may be None for IOC-only cases — save_case_results handles that
            save_case_results(case, mail)
            update_kpi_and_user_stats(case)

            update_cases_logger.info("get_report: case %s completed.", case.id)

        except Exception as exc:
            update_cases_logger.error(
                "get_report: error processing case %s: %s", case.id, exc, exc_info=True
            )

    # ── report processing helpers ─────────────────────────────────────────

    @staticmethod
    def process_analyzer_reports(reports, analyzer_reports, artifact_value, case_id):
        """Process Cortex job outputs and append to the shared reports list."""
        failure_count = 0
        update_cases_logger.info(
            "[reports] Processing %d analyzer reports.", len(analyzer_reports)
        )

        for report in analyzer_reports:
            try:
                if report.status == "Success":
                    CortexAnalyzerReports.create_and_save_report(
                        report, artifact_value, case_id
                    )
                elif report.status == "Failure":
                    failure_count += CortexAnalyzerReports.handle_failure(report)

                update_cases_logger.info(
                    "Processed report id=%s status=%s score=%s confidence=%s.",
                    report.id, report.status, report.score, report.confidence,
                )
                reports.append(report)

            except Exception as exc:
                update_cases_logger.error(
                    "Error processing analyzer report id=%s: %s",
                    getattr(report, "id", "?"), exc, exc_info=True,
                )

        return failure_count

    @staticmethod
    def create_and_save_report(report, artifact_value, case_id):
        """Run the analyzer for a successful job and write scoring fields."""
        try:
            update_cases_logger.info(
                "Creating result for artifact=%r analyzer=%s.",
                artifact_value, report.analyzer.name,
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
                category = ", ".join(str(c) for c in category)

            report.score      = result_dict.get("score",      0)
            report.confidence = result_dict.get("confidence", 0)
            report.category   = category
            report.level      = result_dict.get("level",    "info")

            # Only update the four scoring columns — prevents overwriting
            # foreign keys or timestamps that another process may have changed.
            # AnalyzerReport has no `details` column; raw payload is already in
            # report_full / report_summary / report_taxonomy from initial save.
            report.save(update_fields=["score", "confidence", "category", "level"])

        except Exception as exc:
            update_cases_logger.error(
                "Error saving analyzer report id=%s: %s",
                getattr(report, "id", "?"), exc, exc_info=True,
            )

    @staticmethod
    def handle_failure(report):
        """Record a failed analyzer execution with neutral/baseline scores."""
        report.score      = 5
        report.confidence = 0
        report.category   = "Failed task"
        report.level      = "info"
        report.details    = {}
        report.save(update_fields=["score", "confidence", "category", "level", "details"])
        return 1

    # ── queryset helpers ──────────────────────────────────────────────────

    @staticmethod
    def get_analyzer_reports_by_type_and_artifact(artifact_type, artifact):
        """
        Return the most-recent AnalyzerReport per analyzer for a given
        artifact, as an ORM QuerySet (not a list).

        The subquery stays inside the database — no Python list
        materialisation — so Django can combine it with further filters
        or prefetch_related calls from the caller without extra queries.

        Supported artifact types:
            file, hash, url, ip, domain, mail_body, mail_header, mailaddress
        """
        FIELD_MAP = {
            "file":        "file",
            "hash":        "hash",
            "url":         "url",
            "ip":          "ip",
            "domain":      "domain",
            "mail_body":   "mail_body",
            "mail_header": "mail_header",
            "mailaddress": "mail",      # AnalyzerReport FK is named "mail"
        }

        field_name = FIELD_MAP.get(artifact_type)
        if not field_name:
            update_cases_logger.warning(
                "get_analyzer_reports_by_type_and_artifact: unknown type %r.", artifact_type
            )
            return AnalyzerReport.objects.none()

        # Keep the subquery in SQL — avoids loading all IDs into Python.
        latest_id_subquery = (
            AnalyzerReport.objects
            .filter(**{field_name: artifact})
            .values("analyzer_id")
            .annotate(latest_id=Max("id"))
            .values("latest_id")
        )

        return AnalyzerReport.objects.filter(id__in=latest_id_subquery)