import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerCrowdsec(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if (
                    taxonomy.get("namespace") == "Crowdsec"
                    and taxonomy.get("predicate") == "Threat"
                ):
                    level = taxonomy.get("level", "safe").lower()
                    response["level"] = level
                    response["details"] = {
                        "Crowdsec Threat": taxonomy.get("value", "")
                    }
                    response["score"], response["confidence"] = (
                        get_level_score_confidence(level)
                    )
                    break

        except Exception as exc:
            logger.error("[AnalyzerCrowdsec] error: %s", exc, exc_info=True)

        return response
