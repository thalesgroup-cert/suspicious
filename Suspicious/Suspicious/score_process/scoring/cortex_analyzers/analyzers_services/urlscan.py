import logging
import re
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerUrlscan(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if taxonomy.get("namespace") == "urlscan.io" and taxonomy.get("predicate") == "Search":
                    value = taxonomy.get("value", "")
                    match = re.search(r'(\d+)', value)
                    count = int(match.group(1)) if match else 0

                    details = {"urlscan.io Search Results": count}
                    level = "suspicious" if count > 0 else "safe"

                    response["level"] = level
                    response["details"] = details
                    response["score"], response["confidence"] = get_level_score_confidence(level)
                    break

        except Exception as e:
            logger.error(f"[AnalyzerUrlscan] error: {e}", exc_info=True)

        return response
