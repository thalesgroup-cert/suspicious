import re
import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerVT(BaseAnalyzer):
    def process(self):
        response = super().process()

        best_level = None
        priority = {"safe": 0, "info": 1, "suspicious": 2, "malicious": 3}

        try:
            for taxonomy in self.summary.get("taxonomies", []):
                if taxonomy.get("namespace") != "VT" or taxonomy.get("predicate") != "GetReport":
                    continue

                value = taxonomy.get("value", "")
                ratio = 0.0

                if "/" in value:
                    try:
                        num, den = value.split("/", 1)
                        ratio = int(num.strip()) / max(int(den.strip()), 1)
                    except Exception:
                        ratio = 0.0
                else:
                    match = re.search(r"(\d+)", value)
                    ratio = int(match.group(1)) / 100 if match else 0.0

                if ratio >= 0.5:
                    level = "malicious"
                elif ratio >= 0.1:
                    level = "suspicious"
                else:
                    level = taxonomy.get("level", "safe").lower()

                if best_level is None or priority[level] > priority[best_level]:
                    best_level = level

            if best_level:
                response["level"] = best_level
                response["score"], response["confidence"] = (
                    get_level_score_confidence(best_level)
                )

        except Exception as exc:
            logger.error("[AnalyzerVT] error: %s", exc, exc_info=True)

        return response
