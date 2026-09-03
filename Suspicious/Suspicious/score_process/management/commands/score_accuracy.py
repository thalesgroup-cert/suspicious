"""Run the IOC scoring engine over the labelled fixture set and report accuracy.

Read-only. The fixtures under ``scoring/fixtures/labelled_cases/`` are the
GTI <-> Suspicious comparison cases (spec section 1), each with a validated
``expected_band``. Exits non-zero on any false positive or false negative so a
behaviour change to ``observable_engine`` is caught in CI.
"""
import json
import pathlib
from collections import Counter

from django.core.management.base import BaseCommand

from score_process.scoring.sources import SourceVerdict
from score_process.scoring.observable_engine import score_observable

FIXDIR = pathlib.Path(__file__).resolve().parents[2] / "scoring" / "fixtures" / "labelled_cases"
_RANK = {"Safe": 0, "Inconclusive": 1, "Suspicious": 2, "Dangerous": 3}


class Command(BaseCommand):
    help = "Run the scoring engine over the labelled fixture set and report accuracy."

    def handle(self, *args, **opts):
        tally = Counter()
        for f in sorted(FIXDIR.glob("*.json")):
            d = json.loads(f.read_text())
            sources = [
                SourceVerdict(
                    name=s["name"], tier=s["tier"], weight=s["weight"], verdict=s["verdict"],
                    confidence=s.get("confidence"), failed=s.get("failed", False),
                    evidence=s.get("evidence", ""),
                )
                for s in d["sources"]
            ]
            got, exp = score_observable(sources).band, d["expected_band"]
            if got == exp:
                tally["aligned"] += 1
                verdict = "aligned"
            elif _RANK[got] > _RANK[exp]:
                tally["false_positive"] += 1
                verdict = "FALSE POSITIVE"
            else:
                tally["false_negative"] += 1
                verdict = "FALSE NEGATIVE"
            self.stdout.write(
                f"{d['name']:<45} GTI {d.get('gti_verdict', '?'):<16} "
                f"expected {exp:<12} got {got:<12} {verdict}"
            )
        self.stdout.write(self.style.SUCCESS(f"\n{dict(tally)}"))
        if tally["false_positive"] or tally["false_negative"]:
            raise SystemExit(1)
