import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerAbuseIPDB(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if (
                    taxonomy.get("namespace") == "AbuseIPDB"
                    and taxonomy.get("predicate") == "Records"
                ):
                    try:
                        count = int(taxonomy.get("value", 0))
                    except Exception:
                        count = 0

                    if count > 10:
                        level = "malicious"
                    elif count > 0:
                        level = "suspicious"
                    else:
                        level = "safe"

                    response["level"] = level
                    response["details"] = {"Records": count}
                    response["score"], response["confidence"] = (
                        get_level_score_confidence(level)
                    )
                    break

        except Exception as exc:
            logger.error(
                "[AnalyzerAbuseIPDB] error: %s", exc, exc_info=True
            )

        return response
