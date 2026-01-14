import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerMaxMind(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if (
                    taxonomy.get("namespace") == "MaxMind"
                    and taxonomy.get("predicate") == "Location"
                ):
                    level = taxonomy.get("level", "info").lower()

                    details = {
                        "MaxMind Location": taxonomy.get("value", "")
                    }

                    if self.full:
                        details.update({
                            "City": self.full.get("city", {}),
                            "Continent": self.full.get("continent", {}),
                            "Country": self.full.get("country", {}),
                            "Location": self.full.get("location", {}),
                            "Registered Country": self.full.get("registered_country", {}),
                            "Represented Country": self.full.get("represented_country", {}),
                            "Subdivisions": self.full.get("subdivisions", {}),
                            "Traits": self.full.get("traits", {}),
                        })

                    response["level"] = level
                    response["details"] = details
                    response["score"], response["confidence"] = (
                        get_level_score_confidence(level)
                    )
                    break

        except Exception as exc:
            logger.error("[AnalyzerMaxMind] error: %s", exc, exc_info=True)

        return response
