import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerMN_PDNS(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if (
                    taxonomy.get("namespace") == "MN_PDNS"
                    and taxonomy.get("predicate") == "Public"
                ):
                    level = taxonomy.get("level", "info").lower()

                    details = {
                        "MN_PDNS Public Value": taxonomy.get("value", 0)
                    }

                    if self.full and "findings" in self.full:
                        details.update({
                            "Findings Count": self.full["findings"].get("count", 0),
                            "Data": self.full["findings"].get("data", []),
                        })

                    response["level"] = level
                    response["details"] = details
                    response["score"], response["confidence"] = (
                        get_level_score_confidence(level)
                    )
                    break

        except Exception as exc:
            logger.error("[AnalyzerMN_PDNS] error: %s", exc, exc_info=True)

        return response
