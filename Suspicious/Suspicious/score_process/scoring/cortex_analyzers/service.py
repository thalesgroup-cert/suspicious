import logging

from .analyzers import AnalyzerFactory
from .models import AnalyzerResult

update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class CortexAnalyzerService:
    """
    Entry point for analyzer execution and result normalization.
    """

    @staticmethod
    def create_report(
        summary,
        full,
        analyzer_name,
        data,
        data_type,
        case_id=None,
    ) -> AnalyzerResult:
        """
        Runs an analyzer and returns a normalized AnalyzerResult.
        """
        try:
            update_cases_logger.info(
                "[service] Running analyzer=%s data_type=%s",
                analyzer_name,
                data_type,
            )

            return AnalyzerFactory.run(
                summary=summary,
                full=full,
                analyzer_name=analyzer_name,
                data=data,
                data_type=data_type,
                case_id=case_id,
            )

        except Exception as exc:
            update_cases_logger.error(
                "Analyzer service failure for %s: %s",
                analyzer_name,
                exc,
                exc_info=True,
            )

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                data=data,
                score=0,
                confidence=0,
                category="Unknown",
                level="unknown",
                details={},
            )
