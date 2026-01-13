import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerOTXQuery(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if (
                    taxonomy.get("namespace") == "OTX"
                    and taxonomy.get("predicate") == "Pulses"
                ):
                    try:
                        count = int(taxonomy.get("value", 0))
                    except Exception:
                        count = 0

                    if count == 0:
                        level = "safe"
                    elif count >= 100:
                        level = "suspicious"
                    elif count >= 50:
                        level = "malicious"
                    else:
                        level = "info"

                    response["level"] = level
                    response["details"] = {"Pulses": count}
                    response["score"], response["confidence"] = (
                        get_level_score_confidence(level)
                    )
                    break

        except Exception as exc:
            logger.error("[AnalyzerOTXQuery] error: %s", exc, exc_info=True)

        return response
