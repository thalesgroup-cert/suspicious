import logging
import re
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerYara(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if taxonomy.get("namespace") == "Yara" and taxonomy.get("predicate") == "Match":
                    value = taxonomy.get("value", "")
                    match = re.search(r'(\d+)', value)
                    rule_count = int(match.group(1)) if match else 0

                    level = taxonomy.get("level", "safe").lower()
                    details = {"Yara Rule Matches": rule_count}

                    if self.full and "results" in self.full:
                        details["Yara Full Results"] = self.full["results"]

                    response["level"] = level
                    response["details"] = details
                    response["score"], response["confidence"] = get_level_score_confidence(level)
                    break

        except Exception as e:
            logger.error(f"[AnalyzerYara] error: {e}", exc_info=True)

        return response
