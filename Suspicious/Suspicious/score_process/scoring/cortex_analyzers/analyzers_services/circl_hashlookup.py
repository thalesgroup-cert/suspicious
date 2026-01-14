import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerCIRCLHashLookup(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if (
                    taxonomy.get("namespace") == "CIRCLHashlookup"
                    and taxonomy.get("predicate") == "Result"
                ):
                    value = taxonomy.get("value", "").lower()

                    if value in {"unknown", "unkown"}:
                        level = "info"
                    elif value == "found":
                        level = "suspicious"
                    else:
                        level = taxonomy.get("level", "info").lower()

                    response["level"] = level
                    response["details"] = {
                        "CIRCLHashlookup": taxonomy.get("value", "")
                    }
                    response["score"], response["confidence"] = (
                        get_level_score_confidence(level)
                    )
                    break

        except Exception as exc:
            logger.error(
                "[AnalyzerCIRCLHashLookup] error: %s", exc, exc_info=True
            )

        return response
