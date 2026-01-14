import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerHashdd(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if taxonomy.get("namespace") == "Hashdd" and taxonomy.get("predicate") == "knownlevel":
                    value = taxonomy.get("value", "").strip().lower()
                    level = "info" if value == "unknown" else taxonomy.get("level", "info").lower()

                    response["level"] = level
                    response["details"] = {"knownlevel": taxonomy.get("value", "")}
                    response["score"], response["confidence"] = get_level_score_confidence(level)
                    break

        except Exception as e:
            logger.error(f"[AnalyzerHashdd] error: {e}", exc_info=True)

        return response
