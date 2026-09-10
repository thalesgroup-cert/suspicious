"""Rule-based composition of the analyst + reporter explanation text.
No generated text — parameterised sentence templates keyed on the decisive rule."""
from __future__ import annotations

_RECOMMENDATION = {
    "Dangerous": "Do not interact with it; contact your security team if you already did.",
    "Suspicious": "Avoid interacting with any files or links until the review completes.",
    "Safe": "No threat was found, but stay vigilant — no analysis is fully conclusive.",
    "Inconclusive": "Treat the item with caution until a human review completes.",
}

# rule -> {"analyst": template, "reporter": template}
_RULE_TEMPLATES = {
    "tier1-authoritative-malicious": {
        "analyst": "{source} is an authoritative threat-intelligence source and reported "
                   "this {data_type} malicious — that determines the verdict on its own. "
                   "{n_context} other source(s) were consulted for context.",
        "reporter": "This was confirmed malicious by a trusted threat-intelligence source.",
    },
    "tier2-consensus-malicious": {
        "analyst": "{n_counted} independent strong sources agree this {data_type} is "
                   "malicious.",
        "reporter": "Multiple independent security sources flagged this as malicious.",
    },
    "weighted-malicious-share": {
        "analyst": "The trust-weighted share of sources calling this malicious is "
                   "{share:.0%}, past the threshold for Dangerous.",
        "reporter": "The weight of evidence points to this being malicious.",
    },
    "tier1-authoritative-clean": {
        "analyst": "{source} (authoritative) reports this {data_type} clean and no source "
                   "contradicts it.",
        "reporter": "A trusted threat-intelligence source reports this is not a threat.",
    },
    "trusted-flag-not-decisive": {
        "analyst": "{source} flags this {data_type}, but the evidence is not strong enough "
                   "for a malicious verdict — capped at Suspicious.",
        "reporter": "A security source raised a concern, but it is not confirmed malicious.",
    },
    "contextual-only-flag": {
        "analyst": "Only low-trust / contextual sources flag this {data_type}; the verdict "
                   "is capped at Suspicious.",
        "reporter": "A lower-confidence source raised a concern about this item.",
    },
    "no-flag": {
        "analyst": "No source flags this {data_type}.",
        "reporter": "No security source flagged this item.",
    },
    "thin-coverage": {
        "analyst": "The verdict is Inconclusive: {missing}. There is not enough signal to "
                   "assess this {data_type}.",
        "reporter": "The analyzers could not reach a definitive verdict on this item.",
    },
    "deny-listed": {
        "analyst": "This indicator is on the organisation deny list, which forces a "
                   "Dangerous verdict.",
        "reporter": "This item matches your organisation's block list.",
    },
    "derived-observable-escalation": {
        "analyst": "An observable extracted from this one scored worse and raised the "
                   "verdict to {band}.",
        "reporter": "Something this item leads to was found to be a threat.",
    },
    "group-worst-of": {
        "analyst": "{n_counted} of {n_total} submitted indicator(s) are {band}; the case "
                   "takes the worst.",
        "reporter": "At least one of the submitted indicators is {band}.",
    },
    "weighted-consensus": {
        "analyst": "The trust-weighted average of {n_counted} analyzer result(s) puts this "
                   "case at {band}.",
        "reporter": "The overall weight of the analysis puts this at {band}.",
    },
    "single-strong-signal": {
        "analyst": "One analyzer result carried enough confidence to set the verdict at "
                   "{band}.",
        "reporter": "One part of the analysis was decisive for this verdict.",
    },
    "embedded-ioc-escalation": {
        "analyst": "An indicator embedded in this message scored {band}, which raised the "
                   "case band.",
        "reporter": "A link or attachment in this message was found to be a threat.",
    },
    "ai-classifier-decisive": {
        "analyst": "The AI phishing classifier was the highest-confidence signal and set "
                   "the verdict at {band}.",
        "reporter": "Automated phishing detection was decisive for this verdict.",
    },
    "no-signal": {
        "analyst": "No analyzer flagged anything in this message.",
        "reporter": "No security check flagged this message.",
    },
    "analysis-incomplete": {
        "analyst": "The verdict is Inconclusive: {missing}.",
        "reporter": "The analysis could not be completed for a definitive verdict.",
    },
}

RULE_KEYS = tuple(_RULE_TEMPLATES)

_GENERIC = {
    "analyst": "The verdict is {band}, based on {n_counted} of {n_total} source(s).",
    "reporter": "The analysis result is {band}.",
}


def _confidence_reading(band: str, confidence: int) -> str:
    if band == "Safe" and confidence < 40:
        return ("A low risk score with low confidence does not mean the item is safe — it "
                "means the analyzers could not gather enough signal to be sure. Treat it "
                "as unconfirmed.")
    if confidence >= 70:
        return f"Confidence {confidence}/100: strong corroboration across sources."
    if confidence >= 40:
        return f"Confidence {confidence}/100: moderate corroboration; treat as likely but not certain."
    return f"Confidence {confidence}/100: limited corroboration; treat this verdict as provisional."


def _fill(tmpl: str, band: str, confidence: int, sources, facts: dict) -> str:
    ctx = {"band": band, "confidence": confidence,
           "source": facts.get("source", "a source"),
           "n_context": facts.get("n_context", 0),
           "n_counted": facts.get("n_counted", sum(1 for s in sources if s.counted)),
           "n_total": facts.get("n_total", len(sources)),
           "share": facts.get("share", 0.0),
           "data_type": facts.get("data_type", "indicator"),
           "missing": facts.get("missing", "coverage is thin")}
    return tmpl.format(**ctx)


def compose(rule, band, confidence, sources, **facts):
    t = _RULE_TEMPLATES.get(rule, _GENERIC)
    reading = _confidence_reading(band, confidence)
    analyst = _fill(t["analyst"], band, confidence, sources, facts) + " " + reading
    reporter = _fill(t["reporter"], band, confidence, sources, facts) + " " + \
        _RECOMMENDATION.get(band, _RECOMMENDATION["Inconclusive"])
    return analyst, reporter, reading
