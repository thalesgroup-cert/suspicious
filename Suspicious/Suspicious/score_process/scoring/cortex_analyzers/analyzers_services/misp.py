import logging
import re
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerMISP(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if taxonomy.get("namespace") == "MISP" and taxonomy.get("predicate") == "Search":
                    value = str(taxonomy.get("value", "0"))
                    match = re.search(r'(\d+)', value)
                    count = int(match.group(1)) if match else 0

                    details = {"MISP Events": count}
                    level = taxonomy.get("level", "0")

                    if level == "0":
                        if count >= 4:
                            level = "malicious"
                        elif count > 0:
                            level = "suspicious"
                        else:
                            level = "safe"

                    response["level"] = level
                    response["details"] = details
                    response["score"], response["confidence"] = get_level_score_confidence(level)
                    break

        except Exception as e:
            logger.error(f"[AnalyzerMISP] error: {e}", exc_info=True)

        return response
