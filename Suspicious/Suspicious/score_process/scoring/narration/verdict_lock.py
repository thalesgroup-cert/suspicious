"""Deterministic verdict-lock: renders a case's verdict as fixed, literal
facts for a narration prompt, and validates generated text never asserts a
different band/confidence than the facts it was given.

Pure. No ORM. Never imports Django models — see observable_engine.py for
the same discipline on the scoring side.

Known limitation: this is a lexical, keyword-based check, not semantic
understanding. A narration that contradicts the verdict WITHOUT using any
of the band words below (e.g., calling a Dangerous case "a routine notice,
no action required") will pass validation undetected. Fully closing that
gap would require semantic judgment — i.e., another LLM call — which
defeats the point of a deterministic lock. This is why a human still reads
every narration (see the runbook) rather than trusting PASS alone.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_BAND_WORDS = ("Safe", "Suspicious", "Dangerous", "Inconclusive")
_CONFIDENCE_TOLERANCE = 10  # percentage points
_NEGATION_WINDOW_CHARS = 40
_NEGATION_RE = re.compile(
    r"\b(no|not|none|nothing|never|isn't|aren't|wasn't|weren't|doesn't|didn't|won't|can't|couldn't)\b",
    re.IGNORECASE,
)
_CONFIDENCE_CONTEXT_WORDS = ("confidence", "confident", "certainty", "certain")
_CONFIDENCE_CONTEXT_WINDOW_CHARS = 40


@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    reasons: list = field(default_factory=list)


def render_fixed_facts(verdict: dict) -> str:
    """Literal, non-model-authored block of the case's verdict facts."""
    return (
        "FIXED CASE FACTS (do not alter, restate exactly as given):\n"
        f"- Verdict band: {verdict['band']}\n"
        f"- Score: {verdict['score']} (out of 10)\n"
        f"- Confidence: {verdict['confidence']} (out of 100)\n"
        f"- Decisive rule: {verdict.get('rule', 'unknown')}\n"
    )


def _is_negated(text: str, match_start: int) -> bool:
    """Check the text immediately preceding a match for a negation marker."""
    window_start = max(0, match_start - _NEGATION_WINDOW_CHARS)
    return bool(_NEGATION_RE.search(text[window_start:match_start]))


def _near_confidence_word(text: str, match_start: int, match_end: int) -> bool:
    """Check whether a confidence-related word appears near a percentage match."""
    window_start = max(0, match_start - _CONFIDENCE_CONTEXT_WINDOW_CHARS)
    window_end = match_end + _CONFIDENCE_CONTEXT_WINDOW_CHARS
    context = text[window_start:window_end].lower()
    return any(word in context for word in _CONFIDENCE_CONTEXT_WORDS)


def validate_narration(text: str, verdict: dict) -> ValidationResult:
    """Fails if `text` asserts a band other than verdict['band'] (unless
    negated), or a confidence percentage near a confidence-context word that
    differs from verdict['confidence'] by more than _CONFIDENCE_TOLERANCE
    points. Passes on silence — omitting verdict language entirely is not
    a contradiction. See the module docstring for this check's known limit."""
    reasons = []
    band = verdict["band"]

    for word in _BAND_WORDS:
        if word == band:
            continue
        for match in re.finditer(rf"\b{re.escape(word)}\b", text, re.IGNORECASE):
            if _is_negated(text, match.start()):
                continue
            reasons.append(f"narration mentions contradicting band '{word}' (verdict is '{band}')")
            break

    confidence = verdict.get("confidence")
    if confidence is not None:
        for match in re.finditer(r"(?<![\d.])(\d{1,3}(?:\.\d+)?)\s?%", text):
            if not _near_confidence_word(text, match.start(), match.end()):
                continue
            pct = float(match.group(1))
            if abs(pct - float(confidence)) > _CONFIDENCE_TOLERANCE:
                reasons.append(
                    f"narration states {match.group(1)}% confidence, verdict confidence is {confidence}"
                )

    return ValidationResult(passed=not reasons, reasons=reasons)
