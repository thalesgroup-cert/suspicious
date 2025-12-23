import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerSFS(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if taxonomy.get("namespace") == "SFS" and taxonomy.get("predicate") == "ip":
                    level = taxonomy.get("level", "info").lower()
                    details = {"SFS ip": taxonomy.get("value", "")}

                    if self.full:
                        details.update({
                            "Full IP": self.full.get("value", ""),
                            "Frequency": self.full.get("frequency", 0),
                            "Appears": self.full.get("appears", False),
                            "ASN": self.full.get("asn", ""),
                            "Country": self.full.get("country", "")
                        })

                    response["level"] = level
                    response["details"] = details
                    response["score"], response["confidence"] = get_level_score_confidence(level)
                    break

        except Exception as e:
            logger.error(f"[AnalyzerSFS] error: {e}", exc_info=True)

        return response
