import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerMailHeader(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            severity_order = {"safe": 0, "info": 1, "suspicious": 2, "malicious": 3}
            response.setdefault("details", {})
            response.setdefault("category", [])

            for taxonomy in self.summary.get("taxonomies", []):
                if taxonomy.get("namespace") == "MailHeader":
                    predicate = taxonomy.get("predicate")
                    value = taxonomy.get("value")
                    level = taxonomy.get("level", "info").lower()

                    if predicate:
                        response["details"][predicate] = value
                    if value and value not in response["category"]:
                        response["category"].append(value)

                    current_level = response.get("level", "info").lower()
                    if severity_order.get(level, 0) > severity_order.get(current_level, 0):
                        response["level"] = level

            if self.full:
                response["details"].update({
                    "full_malscore": self.full.get("malscore"),
                    "full_confidence": self.full.get("confidence"),
                    "full_malfamily": self.full.get("malfamily"),
                    "report": self.full.get("report")
                })

            response["score"], response["confidence"] = get_level_score_confidence(response["level"])

        except Exception as e:
            logger.error(f"[AnalyzerMailHeader] error: {e}", exc_info=True)

        return response
