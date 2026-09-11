"""Deterministic verdict-lock: renders a case's verdict as fixed, literal
facts for a narration prompt, and validates generated text never asserts a
different band/confidence than the facts it was given.

Pure. No ORM. Never imports Django models — see observable_engine.py for
the same discipline on the scoring side.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_BAND_WORDS = ("Safe", "Suspicious", "Dangerous", "Inconclusive")
_CONFIDENCE_TOLERANCE = 10  # percentage points


@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    reasons: list = field(default_factory=list)


def render_fixed_facts(verdict: dict) -> str:
    """Literal, non-model-authored block of the case's verdict facts."""
    return (
        "FIXED CASE FACTS (do not alter, restate exactly as given):\n"
        f"- Verdict band: {verdict['band']}\n"
        f"- Score: {verdict['score']}\n"
        f"- Confidence: {verdict['confidence']}\n"
        f"- Decisive rule: {verdict.get('rule', 'unknown')}\n"
    )


def validate_narration(text: str, verdict: dict) -> ValidationResult:
    """Fails if `text` asserts a band other than verdict['band'], or a
    confidence percentage that differs from verdict['confidence'] by more
    than _CONFIDENCE_TOLERANCE points. Passes on silence — omitting verdict
    language entirely is not a contradiction."""
    reasons = []
    band = verdict["band"]

    for word in _BAND_WORDS:
        if word == band:
            continue
        if re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE):
            reasons.append(f"narration mentions contradicting band '{word}' (verdict is '{band}')")

    confidence = verdict.get("confidence")
    if confidence is not None:
        for match in re.finditer(r"(\d{1,3})\s?%", text):
            pct = int(match.group(1))
            if abs(pct - round(float(confidence))) > _CONFIDENCE_TOLERANCE:
                reasons.append(
                    f"narration states {pct}% confidence, verdict confidence is {confidence}"
                )

    return ValidationResult(passed=not reasons, reasons=reasons)
