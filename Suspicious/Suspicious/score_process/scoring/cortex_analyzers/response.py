import logging
from typing import Dict, Any

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

SEVERITY_ORDER = {
    "safe": 0,
    "info": 1,
    "suspicious": 2,
    "malicious": 3,
    "dangerous": 3,
}


def get_level_score_confidence(level: str) -> tuple[int, int]:
    match level:
        case "malicious" | "dangerous":
            return 10, 10
        case "suspicious":
            return 7, 7
        case "info":
            return 5, 5
        case "safe":
            return 0, 10
        case _:
            return 0, 0


def analyze_taxonomy(
    summary: Dict[str, Any],
    response: Dict[str, Any],
    analyzer_name: str,
) -> Dict[str, Any]:
    try:
        taxonomies = summary.get("taxonomies")
        if not taxonomies:
            return response

        response.setdefault("details", {})
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
        logger.error(
            "[%s] taxonomy analysis failed: %s", analyzer_name, exc, exc_info=True
        )

    return response


def analyze_results(
    full: Dict[str, Any],
    response: Dict[str, Any],
    analyzer_name: str,
    category_key: str = "threat",
) -> Dict[str, Any]:
    try:
        results = full.get("results")
        if not isinstance(results, list):
            return response

        response.setdefault("details", {})
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
        logger.error(
            "[%s] result analysis failed: %s", analyzer_name, exc, exc_info=True
        )

    return response


def analyze_whitelist(
    response: Dict[str, Any],
    whitelist_result: str | None,
) -> Dict[str, Any]:
    if not whitelist_result:
        return response

    response["score"] = 0
    response["confidence"] = 10
    response["level"] = "safe"
    response.setdefault("category", []).append(whitelist_result)
    response.setdefault("details", {})["whitelist"] = whitelist_result

    return response


def base_response(
    analyzer_name: str,
    data: str,
    level: str = "info",
    score: int = 5,
    confidence: int = 5,
) -> Dict[str, Any]:
    return {
        "analyzer_name": analyzer_name,
        "data": data,
        "score": score,
        "confidence": confidence,
        "category": [],
        "level": level,
        "details": {},
    }
