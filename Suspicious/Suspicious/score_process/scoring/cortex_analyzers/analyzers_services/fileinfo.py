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
            file_type = None

            for taxonomy in self.summary.get("taxonomies", []):
                if taxonomy.get("namespace") != "FileInfo":
                    continue

                predicate = taxonomy.get("predicate", "unknown")
                value = taxonomy.get("value", "")
                details[predicate] = value

                if predicate.lower() in {"type", "filetype", "mime", "format"} and isinstance(value, str):
                    file_type = value

                level = taxonomy.get("level", "safe").lower()
                if level not in priority:
                    level = "safe"

                if best_level is None or priority[level] > priority[best_level]:
                    best_level = level

            if file_type:
                response["category"] = file_type
            else:
                response["category"] = "FileInfo"

            if best_level:
                response["level"] = best_level
                response["details"] = details
                response["score"], response["confidence"] = get_level_score_confidence(best_level)

        except Exception as exc:
            logger.error("[AnalyzerFileinfo] error: %s", exc)

        return response
