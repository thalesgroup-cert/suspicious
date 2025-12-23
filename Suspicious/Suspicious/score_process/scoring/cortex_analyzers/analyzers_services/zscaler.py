import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerZscaler(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if taxonomy.get("namespace") == "Zscaler" and taxonomy.get("predicate") == "Classification":
                    classification_value = taxonomy.get("value", "").strip()
                    level = taxonomy.get("level", "safe").lower()

                    details = {"Zscaler Classification": classification_value}
                    if self.full:
                        details.update({
                            "URL": self.full.get("url", ""),
                            "URL Classifications": self.full.get("urlClassifications", []),
                            "URL Classifications with Security Alert": self.full.get("urlClassificationsWithSecurityAlert", [])
                        })

                    response["level"] = level
                    response["details"] = details
                    response["score"], response["confidence"] = get_level_score_confidence(level)
                    break

        except Exception as e:
            logger.error(f"[AnalyzerZscaler] error: {e}", exc_info=True)

        return response
