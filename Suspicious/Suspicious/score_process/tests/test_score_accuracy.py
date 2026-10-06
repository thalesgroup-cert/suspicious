import json
import pathlib

from django.test import SimpleTestCase

from score_process.scoring.sources import SourceVerdict
from score_process.scoring.observable_engine import score_observable

FIXDIR = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scoring" / "fixtures" / "labelled_cases"
)


def _sources(data):
    return [
        SourceVerdict(
            name=s["name"], tier=s["tier"], weight=s["weight"], verdict=s["verdict"],
            confidence=s.get("confidence"), failed=s.get("failed", False),
            evidence=s.get("evidence", ""),
        )
        for s in data["sources"]
    ]


class LabelledAccuracyTests(SimpleTestCase):
    def test_every_labelled_case_matches_expected_band(self):
        fixtures = sorted(FIXDIR.glob("*.json"))
        self.assertEqual(len(fixtures), 5, "expected 5 labelled fixtures")
        failures = []
        for f in fixtures:
            data = json.loads(f.read_text())
            got = score_observable(_sources(data)).band
            if got != data["expected_band"]:
                failures.append(
                    f"{data['name']}: expected {data['expected_band']}, got {got}"
                )
        self.assertEqual(failures, [], "\n".join(failures))
