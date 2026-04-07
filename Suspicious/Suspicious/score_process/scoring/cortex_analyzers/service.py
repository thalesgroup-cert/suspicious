# analyzers_services/service.py
"""
Cortex analyzer service — single entry point for running an analyzer
and returning a normalised AnalyzerResult.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .analyzers import AnalyzerExecutionError, AnalyzerFactory
from .models import AnalyzerResult

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class CortexAnalyzerService:
    """Entry point for analyzer execution and result normalisation."""

    @staticmethod
    def create_report(
        summary: Any,
        full: Any,
        analyzer_name: str,
        data: Any,
        data_type: str,
        case_id: Optional[int] = None,
    ) -> AnalyzerResult:
        """
        Run an analyzer and return a normalised AnalyzerResult.

        AnalyzerExecutionError from AnalyzerFactory.run() is allowed to
        propagate — the caller (CortexAnalyzerReports.create_and_save_report)
        catches it and routes to handle_failure().

        Any other unexpected exception is caught here as a safety net and
        returns a neutral failed result.
        """
        logger.info(
            "[service] Running analyzer=%s data_type=%s.",
            analyzer_name,
            data_type,
        )

        try:
            return AnalyzerFactory.run(
                summary=summary,
                full=full,
                analyzer_name=analyzer_name,
                data=data,
                data_type=data_type,
                case_id=case_id,
            )
        except AnalyzerExecutionError:
            # Re-raise so CortexAnalyzerReports routes to handle_failure()
            raise
        except Exception as exc:
            # Unexpected infrastructure failure (import error, DB error, etc.)
            logger.error(
                "Unexpected service failure for analyzer %s: %s",
                analyzer_name,
                exc,
                exc_info=True,
            )
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                data=str(data),
                score=0,
                confidence=0,
                category="Unknown",
                level="unknown",
                details={},
            )