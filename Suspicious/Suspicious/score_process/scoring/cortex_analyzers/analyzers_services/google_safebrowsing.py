import re
import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerGoogleSafeBrowsing(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            level = "safe"
            details = {}

            for taxonomy in self.summary.get("taxonomies", []):
                if (
                    taxonomy.get("namespace") == "Google"
                    and taxonomy.get("predicate") == "Safebrowsing"
                ):
                    value = taxonomy.get("value", "")
                    details["Safebrowsing"] = value

                    match = re.search(r"(\d+)", value)
                    count = int(match.group(1)) if match else 0
                    level = "suspicious" if count > 0 else "safe"
                    break

            response["level"] = level
            response["details"] = details
            response["score"], response["confidence"] = (
                get_level_score_confidence(level)
            )

        except Exception as exc:
            logger.error(
                "[AnalyzerGoogleSafeBrowsing] error: %s", exc, exc_info=True
            )

        return response
