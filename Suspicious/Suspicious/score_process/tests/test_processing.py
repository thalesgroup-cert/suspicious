from django.test import SimpleTestCase

from score_process.scoring.processing import compute_weighted_scores


class _Analyzer:
    def __init__(self, weight):
        self.weight = weight


class _Report:
    def __init__(self, score, confidence, weight, status="Success"):
        self.score = score
        self.confidence = confidence
        self.status = status
        self.analyzer = _Analyzer(weight)


class ComputeWeightedScoresScaleTest(SimpleTestCase):
    def test_weighted_confidence_is_0_100_scale(self):
        """A report with confidence=100 must yield weighted_confidence=100,
        not 1000 — confidence is a single 0-100 scale end to end."""
        _, weighted_confidence, _ = compute_weighted_scores(
            [_Report(score=10, confidence=100, weight=1)], "url"
        )
        self.assertEqual(weighted_confidence, 100)

    def test_weighted_confidence_weighted_average(self):
        _, weighted_confidence, _ = compute_weighted_scores(
            [_Report(10, 80, 1), _Report(0, 40, 1)], "url"
        )
        self.assertEqual(weighted_confidence, 60)
