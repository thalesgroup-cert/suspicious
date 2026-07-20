"""
Analyzer report lifecycle: execution, persistence, and querying.
"""
import logging

from django.db.models import Max

from cortex_job.models import AnalyzerReport
from .utils import dump_model

update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class CortexAnalyzerReports:
    """Handles persistence and lifecycle of analyzer reports."""

    # ── public pipeline entry point ───────────────────────────────────────

    @staticmethod
    def get_report(case) -> None:
        """
        Score a case end-to-end: collect signals (which also persists
        analyzer reports), compute the verdict, and apply it (persist,
        notify, KPI).
        """
        from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
        from score_process.scoring.collect import collect_signals
        from score_process.scoring.engine import score_case
        from score_process.scoring.apply import apply_verdict

        if not case:
            update_cases_logger.warning("get_report called with no case.")
            return

        try:
            mail = getattr(case.fileOrMail, "mail", None) if case.fileOrMail else None
            if mail:
                CortexJobManager().manage_ai_jobs(case)

            signals, ai, deny_listed, ai_missing = collect_signals(case)
            verdict = score_case(signals, ai, deny_listed, ai_missing)
            apply_verdict(case, verdict)

            update_cases_logger.info(
                "get_report: case %s → %s (score=%s conf=%s, %d/%d malicious).",
                case.id, verdict.result, verdict.final_score,
                verdict.final_confidence, verdict.n_malicious, verdict.n_scored,
            )

        except Exception as exc:
            update_cases_logger.error(
                "get_report: error scoring case %s: %s", case.id, exc, exc_info=True
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
        """Run the resolved parser for a finished job and write scoring fields.

        PENDING (job not finished) → leave the row untouched for the next poll.
        Only update the four scoring columns — prevents overwriting foreign keys
        or timestamps another process may have changed. AnalyzerReport has no
        `details` column; raw payload is already in report_full / report_summary.
        """
        from .registry import registry
        from .result import PENDING
        try:
            update_cases_logger.info(
                "Creating result for artifact=%r analyzer=%s.",
                artifact_value, report.analyzer.name,
            )

            parser_cls = registry.resolve(report.analyzer)
            parser = parser_cls(
                analyzer_name=report.analyzer.name,
                data=artifact_value,
                data_type=report.type,
                case_id=case_id,
            )
            result = parser.run(report.report_summary, report.report_full, report.status)
            if result is PENDING:
                update_cases_logger.info(
                    "Report %s still pending — not scoring.", getattr(report, "id", "?"))
                return

            result_dict = dump_model(result)
            category = result_dict.get("category", "Unknown")
            if isinstance(category, list):
                category = ", ".join(str(c) for c in category)

            report.score      = result_dict.get("score",      0)
            report.confidence = result_dict.get("confidence", 0)
            report.category   = category
            report.level      = result_dict.get("level",    "info")
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
        report.save(update_fields=["score", "confidence", "category", "level"])
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
            "mailaddress": "mail",
        }

        field_name = FIELD_MAP.get(artifact_type)
        if not field_name:
            update_cases_logger.warning(
                "get_analyzer_reports_by_type_and_artifact: unknown type %r.", artifact_type
            )
            return AnalyzerReport.objects.none()

        latest_id_subquery = (
            AnalyzerReport.objects
            .filter(**{field_name: artifact})
            .values("analyzer_id")
            .annotate(latest_id=Max("id"))
            .values("latest_id")
        )

        return AnalyzerReport.objects.filter(id__in=latest_id_subquery)