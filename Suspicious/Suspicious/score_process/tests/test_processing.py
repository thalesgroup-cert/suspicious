from unittest.mock import patch

from django.test import SimpleTestCase, TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from file_process.models import File
from hash_process.models import Hash
from score_process.scoring.processing import compute_weighted_scores, process_file_ioc


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


class FileHashCombinedConfidenceScaleTest(TestCase):
    """Characterise the combined file+hash confidence path at the 0-100 scale.

    The T7 confidence-scale refactor is NOT exact identity here: the branch
    nests round(compute_weighted_scores(...)) inside another round() of the
    file/hash blend, so it can diverge from the honest single weighted mean of
    every report by up to 1 unit. This locks that the divergence stays bounded
    (<= 1) and that file_confidence stays in 0..100.
    """

    def _report(self, analyzer, *, file=None, hash=None, score, confidence):
        return AnalyzerReport.objects.create(
            cortex_job_id=f"j-{analyzer.name}", type="file" if file else "hash",
            status="Success", analyzer=analyzer, file=file, hash=hash,
            level="suspicious", confidence=confidence, score=score,
            report_summary={}, report_taxonomy={}, report_full={},
        )

    def test_combined_confidence_matches_weighted_mean_within_one(self):
        h = Hash.objects.create(value="sha256-combined-conf")
        f = File.objects.create(
            linked_hash=h, file_path="files/combined-conf.bin",
            tmp_path="", other_names="",
        )
        af1 = Analyzer.objects.create(name="FileA", analyzer_cortex_id="FileA", weight=0.3)
        af2 = Analyzer.objects.create(name="FileB", analyzer_cortex_id="FileB", weight=0.7)
        ah1 = Analyzer.objects.create(name="HashA", analyzer_cortex_id="HashA", weight=0.5)
        self._report(af1, file=f, score=6, confidence=80)
        self._report(af2, file=f, score=4, confidence=55)
        self._report(ah1, hash=h, score=8, confidence=90)

        with patch(
            "score_process.scoring.cortex_analyzers.reports."
            "CortexAnalyzerReports.process_analyzer_reports",
            return_value=0,
        ):
            failures = process_file_ioc(f, [], [], [], False, 1)

        self.assertEqual(failures, 0)
        f.refresh_from_db()
        # honest single weighted mean of every report by analyzer weight
        expected = (80 * 0.3 + 55 * 0.7 + 90 * 0.5) / (0.3 + 0.7 + 0.5)
        self.assertGreaterEqual(f.file_confidence, 0)
        self.assertLessEqual(f.file_confidence, 100)
        self.assertLessEqual(abs(f.file_confidence - expected), 1)
