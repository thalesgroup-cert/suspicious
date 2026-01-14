import logging
import re
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerURLhaus(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if taxonomy.get("namespace") == "URLhaus" and taxonomy.get("predicate") == "Search":
                    value = taxonomy.get("value", "")
                    details = {"URLhaus Search": value}

                    if "no results" in value.lower():
                        level = "safe"
                    else:
                        match = re.search(r'(\d+)', value)
                        count = int(match.group(1)) if match else 0
                        level = "suspicious" if count > 0 else taxonomy.get("level", "info").lower()

                    response["level"] = level
                    response["details"] = details
                    response["score"], response["confidence"] = get_level_score_confidence(level)
                    break

        except Exception as e:
            logger.error(f"[AnalyzerURLhaus] error: {e}", exc_info=True)

        return response
