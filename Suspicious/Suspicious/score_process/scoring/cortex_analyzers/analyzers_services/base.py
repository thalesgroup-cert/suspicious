# analyzers_services/base.py
"""
Base analyzer — shared initialization, whitelist check, and taxonomy/result
analysis pipeline that all concrete analyzers build on.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from score_process.scoring.cortex_analyzers.response import (
    analyze_results,
    analyze_taxonomy,
    analyze_whitelist,
    base_response,
)
from score_process.scoring.cortex_analyzers.allow_list import check_allow_list

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class BaseAnalyzer:
    """
    Shared base for all Cortex analyzer wrappers.

    Subclasses override process() and call super().process() to get a
    pre-populated response dict, then add or modify fields before
    returning.

    process() is intentionally stateless between calls — each call
    returns a fresh dict so the instance can be reused safely.
    """

    def __init__(
        self,
        summary: Any,
        full: Any,
        data: Any,
        analyzer_name: str,
        data_type: Optional[str] = None,
        case_id: Optional[int] = None,
        data_name: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        self.summary          = summary
        self.full             = full
        self.data             = data
        # Coerce to string — some callers pass Path or int objects
        self.data_name        = data_name or str(data)
        self.analyzer_name    = analyzer_name
        self.type             = data_type
        self.suspicious_case_id = case_id

    def __repr__(self) -> str:
        return "%s(analyzer=%r type=%r case=%s)" % (
            self.__class__.__name__,
            self.analyzer_name,
            self.type,
            self.suspicious_case_id,
        )

    def process(self) -> Dict[str, Any]:
        """
        Run the base pipeline and return a fresh response dict.

        Pipeline:
          1. Build a neutral baseline response.
          2. Check allow-lists — if a match is found, return immediately
             with a fully-scored "safe" response (score=0 confidence=100).
          3. Apply taxonomy analysis (if summary is available).
          4. Apply results analysis (if full report is available).

        Subclasses call super().process() to receive the dict, then
        augment or override specific fields.
        """
        logger.debug("[%s] start processing.", self.analyzer_name)

        # Build a fresh dict on every call — no shared mutable state
        response: Dict[str, Any] = base_response(self.analyzer_name, self.data_name)

        # ── Allow-list check ──────────────────────────────────────────────
        try:
            whitelist = check_allow_list(self.data_name, self.type)
            for value in whitelist.model_dump().values():
                if value is not None:
                    # analyze_whitelist sets score=0 confidence=100 level=safe
                    logger.debug(
                        "[%s] allow-list match: %r.", self.analyzer_name, value
                    )
                    return analyze_whitelist(response, value)
        except Exception as exc:
            logger.error(
                "[%s] allow-list check error: %s", self.analyzer_name, exc,
                exc_info=True,
            )

        # ── Taxonomy analysis ─────────────────────────────────────────────
        # Guard: summary may be None when Cortex returns no summary object.
        if self.summary:
            response = analyze_taxonomy(self.summary, response, self.analyzer_name)

        # ── Results analysis ──────────────────────────────────────────────
        # Guard: full may be None for lightweight analyzers.
        if self.full:
            response = analyze_results(self.full, response, self.analyzer_name)

        logger.debug("[%s] end processing.", self.analyzer_name)
        return response