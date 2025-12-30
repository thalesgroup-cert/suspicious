# cortex_analyzers/analyzers/base.py
from score_process.scoring.cortex_analyzers.response import (
    base_response,
    analyze_taxonomy,
    analyze_results,
    analyze_whitelist,
)
from score_process.scoring.cortex_analyzers.allowlist import check_allow_list
import logging

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class BaseAnalyzer:
    def __init__(
        self,
        summary,
        full,
        data,
        analyzer_name,
        data_type=None,
        case_id=None,
        data_name=None,
        **kwargs,
    ):
        self.summary = summary
        self.full = full
        self.data = data
        self.data_name = data_name or data
        self.analyzer_name = analyzer_name
        self.type = data_type
        self.suspicious_case_id = case_id
        self.response = base_response(analyzer_name, self.data_name)

    def process(self):
        logger.debug("[%s] start processing", self.analyzer_name)

        try:
            whitelist = check_allow_list(self.data_name, self.type)

            for _, value in whitelist.model_dump().items():
                if value is not None:
                    return analyze_whitelist(self.response, value)
        except Exception as exc:
            logger.error("[%s] whitelist error: %s", self.analyzer_name, exc)

        self.response = analyze_taxonomy(
            self.summary, self.response, self.analyzer_name
        )
        self.response = analyze_results(
            self.full, self.response, self.analyzer_name
        )

        logger.debug("[%s] end processing", self.analyzer_name)
        return self.response
