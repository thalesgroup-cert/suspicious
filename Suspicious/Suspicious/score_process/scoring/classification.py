"""Case-level threat classification, derived on read from data already stored.

Mail cases carry the AI category. Everything else falls back to VirusTotal's
popular threat classification, which the VT enrichment extracts into
``AnalyzerReport.enrichment`` (``threat_category`` / ``threat_label``).
"""
from __future__ import annotations

from collections import defaultdict

_UNSET = {"", "uncategorized", "unknown"}


def derive_threat_classification(case, reports) -> dict | None:
    """``{"label", "category", "source"}`` or None when nothing is known.

    ``reports`` are the case's latest report per analyzer and target. The VT
    category with the most summed report confidence wins; a report with zero
    confidence still counts a little, so a lone low-confidence hit is not lost.
    """
    ai = (getattr(case, "category_ai", "") or "").strip()
    if ai.lower() not in _UNSET:
        return {"label": ai, "category": ai, "source": "ai"}

    weight: dict[str, float] = defaultdict(float)
    labels: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for report in reports:
        enrichment = report.enrichment if isinstance(report.enrichment, dict) else {}
        category = str(enrichment.get("threat_category") or "").strip()
        if not category:
            continue
        w = max(float(report.confidence or 0), 1.0)
        weight[category] += w
        label = str(enrichment.get("threat_label") or "").strip()
        if label:
            labels[category][label] += w
    if not weight:
        return None
    category = max(weight, key=weight.get)
    label = max(labels[category], key=labels[category].get) if labels[category] else category
    return {"label": label, "category": category, "source": "virustotal"}
