"""Categorical trust-weighted verdict engine for the IOC road.

Pure. No ORM — no queries, no writes. Consumes ``SourceVerdict`` (one vote per
analyzer) and returns an ``ObservableVerdict`` band. Never imports
``score_process.scoring.engine``: the mail road is untouched.

Ported from ``docs/specs/verdict-prototype.py`` (spec §4.2, validated against
the 5 GTI-comparison cases).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from score_process.scoring.sources import SourceVerdict

HIGH_CONFIDENCE = 70
DANGEROUS_SHARE = 0.5
MIN_TRUSTED_COVERAGE = 1
TIER_MULTIPLIER = {1: 4, 2: 2, 3: 1}

_FLAGGED = ("malicious", "suspicious")


@dataclass(frozen=True)
class ObservableVerdict:
    band: str            # "Dangerous" | "Suspicious" | "Safe" | "Inconclusive"
    confidence: int      # 0-100
    inconclusive_reason: Optional[str]   # "thin_coverage" | None
    counts: dict         # {"malicious": n, "suspicious": n, "clean": n, "no-data": n}
    rationale: list


def _mult(s: SourceVerdict) -> float:
    return s.weight * TIER_MULTIPLIER.get(s.tier, 1)


def _confidence(sources, split: Optional[float] = None) -> int:
    voting = [s for s in sources if s.verdict != "no-data"]
    if not voting:
        return 0
    total_w = sum(_mult(s) for s in voting) or 1.0
    mal_w = sum(_mult(s) for s in voting if s.verdict == "malicious")
    clean_w = sum(_mult(s) for s in voting if s.verdict == "clean")
    lopsided = (1.0 - split) if split is not None else abs(mal_w - clean_w) / total_w
    trusted = [s for s in voting if s.tier in (1, 2)]
    coverage = min(1.0, len(trusted) / 3.0)
    fail_pen = min(0.6, sum(0.3 if s.tier == 1 else 0.1 for s in sources if s.failed))
    return max(0, min(100, round(lopsided * (0.4 + 0.6 * coverage) * (1.0 - fail_pen) * 100)))


def score_observable(sources: list) -> ObservableVerdict:
    counts = {"malicious": 0, "suspicious": 0, "clean": 0, "no-data": 0}
    for s in sources:
        counts[s.verdict] = counts.get(s.verdict, 0) + 1
    voting = [s for s in sources if s.verdict != "no-data"]
    trusted_voting = [s for s in voting if s.tier in (1, 2)]
    rationale: list = []

    t1_mal = [s for s in trusted_voting if s.tier == 1 and s.verdict == "malicious"]
    t2_mal = [s for s in trusted_voting if s.tier == 2 and s.verdict == "malicious"]
    t1_clean = [s for s in trusted_voting if s.tier == 1 and s.verdict == "clean"]
    trusted_flag = [s for s in trusted_voting if s.verdict in _FLAGGED]
    any_flag = [s for s in voting if s.verdict in _FLAGGED]
    t3_malicious = [s for s in voting if s.tier == 3 and s.verdict == "malicious"]

    # Rule 0 — coverage: too few trusted sources voted, and nothing flags the
    # indicator, so there is no signal to assess. A contextual (Tier-3) flag is
    # still enough signal to route to Suspicious/Dangerous below rather than
    # bury it as Inconclusive (spec §4.2: "Tier-3-only evidence caps at
    # Suspicious").
    if len(trusted_voting) < MIN_TRUSTED_COVERAGE and not any_flag:
        rationale.append(
            f"Only {len(trusted_voting)} trusted source(s) returned a verdict — cannot assess."
        )
        return ObservableVerdict("Inconclusive", _confidence(sources, split=1.0),
                                 "thin_coverage", counts, rationale)

    total_w = sum(_mult(s) for s in voting) or 1.0
    share = sum(_mult(s) for s in voting if s.verdict == "malicious") / total_w

    # Rule 1 — Dangerous
    decisive_t1 = [s for s in t1_mal if s.confidence is None or s.confidence >= HIGH_CONFIDENCE]
    if decisive_t1:
        rationale.append(f"{decisive_t1[0].name} (authoritative) reports malicious.")
        return ObservableVerdict("Dangerous", _confidence(sources), None, counts, rationale)
    if len(t2_mal) >= 2:
        rationale.append(f"{len(t2_mal)} strong sources agree the indicator is malicious.")
        return ObservableVerdict("Dangerous", _confidence(sources), None, counts, rationale)
    if share >= DANGEROUS_SHARE:
        rationale.append(f"Trust-weighted malicious share is {share:.0%}.")
        return ObservableVerdict("Dangerous", _confidence(sources), None, counts, rationale)

    # Rule 2 — Safe: a Tier-1 clean verdict beats Tier-3 noise (e.g. Urlscan_io_Search
    # returns "suspicious" for every URL with >=1 prior scan). A Tier-3 *malicious*
    # still blocks Safe (-> Rule 3 caps at Suspicious); a Tier-3 *suspicious* alone
    # does not.
    if t1_clean and not trusted_flag and not t3_malicious:
        note = "" if not any_flag else " (low-trust noise overridden)"
        rationale.append(
            f"{t1_clean[0].name} (authoritative) reports clean; no trusted source flags it{note}."
        )
        return ObservableVerdict("Safe", _confidence(sources), None, counts, rationale)

    # Rule 3 — Suspicious: something flagged it, not enough for Dangerous.
    if any_flag:
        if trusted_flag:
            rationale.append(f"{trusted_flag[0].name} flags the indicator; evidence is not decisive.")
        else:
            rationale.append("Only contextual/low-trust sources flag this — capped at Suspicious.")
        return ObservableVerdict("Suspicious", _confidence(sources), None, counts, rationale)

    # Nothing flagged at all.
    rationale.append("No source flags the indicator.")
    return ObservableVerdict("Safe", _confidence(sources), None, counts, rationale)
