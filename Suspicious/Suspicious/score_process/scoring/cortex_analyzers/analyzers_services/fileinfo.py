# cortex_analyzers/analyzers/fileinfo.py
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence
import logging

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerFileinfo(BaseAnalyzer):
    def process(self):
        response = super().process()

        best_level = None
        details = {}
        priority = {"safe": 0, "info": 1, "suspicious": 2, "malicious": 3}

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if taxonomy.get("namespace") != "FileInfo":
                    continue

                predicate = taxonomy.get("predicate", "unknown")
                details[predicate] = taxonomy.get("value", "")

                level = taxonomy.get("level", "safe").lower()
                if best_level is None or priority[level] > priority[best_level]:
                    best_level = level

            if best_level:
                response["level"] = best_level
                response["details"] = details
                response["score"], response["confidence"] = (
                    get_level_score_confidence(best_level)
                )

        except Exception as exc:
            logger.error("[AnalyzerFileinfo] error: %s", exc)

        return response
