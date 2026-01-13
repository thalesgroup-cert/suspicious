import re
import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerDShield(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if (
                    taxonomy.get("namespace") == "DShield"
                    and taxonomy.get("predicate") == "Score"
                ):
                    value = taxonomy.get("value", "")

                    pattern = (
                        r"(\d+)\s*count\(s\)\s*/\s*"
                        r"(\d+)\s*attack\(s\)\s*/\s*"
                        r"(\d+)\s*threatfeed\(s\)"
                    )
                    match = re.search(pattern, value, re.IGNORECASE)

                    if not match:
                        logger.error(
                            "[AnalyzerDShield] Unable to parse score: %s", value
                        )

                    level = taxonomy.get("level", "safe").lower()

                    response["level"] = level
                    response["details"] = {
                        "DShield Score": value,
                        "IP": self.full.get("ip", ""),
                        "Count": self.full.get("count", 0),
                        "Attacks": self.full.get("attacks", 0),
                        "Threatfeeds Count": self.full.get(
                            "threatfeedscount", 0
                        ),
                        "Reputation": self.full.get("reputation", ""),
                    }
                    response["score"], response["confidence"] = (
                        get_level_score_confidence(level)
                    )
                    break

        except Exception as exc:
            logger.error("[AnalyzerDShield] error: %s", exc, exc_info=True)

        return response
