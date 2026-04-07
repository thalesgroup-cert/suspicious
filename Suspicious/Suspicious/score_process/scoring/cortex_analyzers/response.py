# score_process/scoring/cortex_analyzers/response.py
"""
Shared scoring helpers used by all analyzer implementations.
"""
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

# ── Severity ordering ─────────────────────────────────────────────────────────
# Used by analyze_taxonomy to pick the highest-severity level seen.
# "malicious" is the analyzer-level term; "dangerous" is the case-level term.
# Both map to the same severity so either can appear in taxonomy output.

SEVERITY_ORDER: Dict[str, int] = {
    "safe":      0,
    "info":      1,
    "suspicious": 2,
    "malicious": 3,
    "dangerous": 3,   # synonym — same severity as malicious
}


# ── Level → score/confidence mapping ─────────────────────────────────────────
# Confidence uses the 0-100 scale consistent with case_score_calculation.py.

def get_level_score_confidence(level: str) -> tuple[int, int]:
    """
    Return (score, confidence) for a named severity level.

    Both values are on a 0-10 / 0-100 scale respectively, matching the
    scales used throughout the scoring pipeline.
    """
    match level:
        case "malicious" | "dangerous":
            return 10, 100
        case "suspicious":
            return 7, 70
        case "info":
            return 5, 50
        case "safe":
            return 0, 100   # High confidence that it is safe
        case _:
            return 0, 0


# ── Analysis helpers ──────────────────────────────────────────────────────────

def analyze_taxonomy(
    summary: Dict[str, Any],
    response: Dict[str, Any],
    analyzer_name: str,
) -> Dict[str, Any]:
    """
    Merge Cortex taxonomy entries into the response dict, raising the level
    to the highest severity seen.
    """
    try:
        taxonomies = summary.get("taxonomies")
        if not taxonomies:
            return response

        response.setdefault("details",  {})
        response.setdefault("category", [])

        for taxonomy in taxonomies:
            value = taxonomy.get("value")
            level = taxonomy.get("level", "info").lower()

            current_level = response.get("level", "info").lower()
            if SEVERITY_ORDER.get(level, 0) > SEVERITY_ORDER.get(current_level, 0):
                response["level"] = level

            if value and value not in response["category"]:
                response["category"].append(value)

            predicate = taxonomy.get("predicate")
            if predicate:
                response["details"][predicate] = value

        response["score"], response["confidence"] = get_level_score_confidence(
            response.get("level", "info")
        )

    except Exception as exc:
        logger.error("[%s] taxonomy analysis failed: %s", analyzer_name, exc, exc_info=True)

    return response


def analyze_results(
    full: Dict[str, Any],
    response: Dict[str, Any],
    analyzer_name: str,
    category_key: str = "threat",
) -> Dict[str, Any]:
    """Merge free-form result entries into the response dict."""
    try:
        results = full.get("results")
        if not isinstance(results, list):
            return response

        response.setdefault("details",  {})
        response.setdefault("category", [])

        for element in results:
            if isinstance(element, dict):
                threat = element.get(category_key)
                if threat and threat not in response["category"]:
                    response["category"].append(threat)
                for k, v in element.items():
                    response["details"].setdefault(k, v)
            else:
                response["category"].append(element)
                response["details"].setdefault("raw_results", []).append(element)

    except Exception as exc:
        logger.error("[%s] result analysis failed: %s", analyzer_name, exc, exc_info=True)

    return response


def analyze_whitelist(
    response: Dict[str, Any],
    whitelist_result: Optional[str],
) -> Dict[str, Any]:
    """
    Override scoring when the artifact matches an allow-list entry.

    Confidence is set to 100 (not 10) — matching the 0-100 scale used
    everywhere else so the weighted average in compute_weighted_scores
    is not distorted.
    """
    if not whitelist_result:
        return response

    response["score"]      = 0
    response["confidence"] = 100
    response["level"]      = "safe"
    response.setdefault("category", []).append(whitelist_result)
    response.setdefault("details",  {})["whitelist"] = whitelist_result

    return response


def base_response(
    analyzer_name: str,
    data: str,
    level: str = "info",
    score: int = 5,
    confidence: int = 50,
) -> Dict[str, Any]:
    """
    Return a neutral baseline response dict.

    Default confidence changed from 5 to 50 to match the 0-100 scale.
    """
    return {
        "analyzer_name": analyzer_name,
        "data":          str(data),   # ensure string even if caller passes a Path
        "score":         score,
        "confidence":    confidence,
        "category":      [],
        "level":         level,
        "details":       {},
    }