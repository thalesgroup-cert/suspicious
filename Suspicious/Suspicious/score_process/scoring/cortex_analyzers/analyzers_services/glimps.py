import logging
from .base import BaseAnalyzer
from score_process.scoring.cortex_analyzers.response import get_level_score_confidence

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerGMalware(BaseAnalyzer):
    """
    Cortex analyzer service for GMalware.

    Scoring principles:
    - Deterministic and explainable
    - Multi-factor (no single field decides alone, except hard overrides)
    - Conservative when signals conflict
    """

    def process(self):
        response = super().process()

        priority = {"safe": 0, "info": 1, "suspicious": 2, "malicious": 3}
        best_level = None

        try:
            summary = self.summary or {}
            full = self.full or {}

            # --- Extract summary signal ---
            summary_level = None
            for taxonomy in summary.get("taxonomies", []):
                if (
                    taxonomy.get("namespace") == "GMalware"
                    and taxonomy.get("predicate") == "Match"
                ):
                    summary_level = taxonomy.get("level", "info").lower()
                    break

            # --- Extract full report signals ---
            is_malware = full.get("is_malware")
            score = full.get("score")
            filetype = full.get("filetype")
            file_count = full.get("file_count")
            files = full.get("files", [])
            status = full.get("status")
            done = full.get("done")

            # Normalize missing values
            if not isinstance(score, (int, float)):
                score = None
            if not isinstance(file_count, int):
                file_count = 0

            # --- Initialize weighted indicators ---
            malicious_weight = 0
            suspicious_weight = 0
            info_weight = 0

            # --- Hard failures / inconsistencies ---
            if status is False or done is False:
                # Analyzer did not complete cleanly
                suspicious_weight += 2

            # --- Malware boolean signal ---
            if is_malware is True:
                malicious_weight += 5
            elif is_malware is False:
                info_weight += 1

            # --- Numeric score interpretation ---
            # score is assumed to be non-negative, higher = worse
            if score is not None:
                if score >= 70:
                    malicious_weight += 4
                elif score >= 30:
                    suspicious_weight += 3
                elif score > 0:
                    suspicious_weight += 1
                else:
                    info_weight += 1

            # --- File-level inspection ---
            for f in files:
                if f.get("is_malware") is True:
                    malicious_weight += 3
                elif f.get("is_malware") is False:
                    info_weight += 0.5

            # --- File type heuristics ---
            # Executable-like content is higher risk than documents
            if isinstance(filetype, str):
                if any(x in filetype for x in ["exe", "dll", "elf", "msi", "script"]):
                    suspicious_weight += 2
                elif any(x in filetype for x in ["pdf", "document", "image", "text"]):
                    info_weight += 0.5

            # --- File count heuristic ---
            if file_count > 1:
                suspicious_weight += 1

            # --- Summary vs full mismatch ---
            if summary_level:
                if summary_level == "safe" and malicious_weight > 0:
                    suspicious_weight += 2
                elif summary_level in ("suspicious", "malicious") and malicious_weight == 0:
                    suspicious_weight += 1

            # --- Determine final level ---
            if malicious_weight >= 5:
                level = "malicious"
            elif malicious_weight > 0 or suspicious_weight >= 3:
                level = "suspicious"
            elif suspicious_weight > 0 or info_weight > 0:
                level = "info"
            else:
                level = "safe"

            best_level = level

            if best_level:
                response["level"] = best_level
                response["score"], response["confidence"] = (
                    get_level_score_confidence(best_level)
                )

        except Exception as exc:
            logger.error("[AnalyzerGMalware] error: %s", exc, exc_info=True)

        return response
