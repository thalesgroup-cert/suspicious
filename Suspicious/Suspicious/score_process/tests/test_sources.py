from types import SimpleNamespace

from django.test import SimpleTestCase

from score_process.scoring.sources import SourceVerdict, source_verdict_from_report


def _report(level="safe", status="Success", confidence=100, category=None, name="X", tier=3, weight=0.2):
    return SimpleNamespace(
        level=level, status=status, confidence=confidence,
        category=",".join(category or []),
        report_full={}, analyzer=SimpleNamespace(name=name, tier=tier, weight=weight),
    )


class SourceVerdictTests(SimpleTestCase):
    def test_malicious_level_maps_to_malicious(self):
        sv = source_verdict_from_report(_report(level="malicious", category=["C2"]))
        self.assertEqual(sv.verdict, "malicious")
        self.assertEqual(sv.evidence, "C2")
        self.assertFalse(sv.failed)

    def test_dangerous_level_maps_to_malicious(self):
        self.assertEqual(source_verdict_from_report(_report(level="dangerous")).verdict, "malicious")

    def test_safe_maps_to_clean(self):
        self.assertEqual(source_verdict_from_report(_report(level="safe")).verdict, "clean")

    def test_suspicious_maps_to_suspicious(self):
        self.assertEqual(source_verdict_from_report(_report(level="SUSPICIOUS ")).verdict, "suspicious")

    def test_info_and_empty_map_to_no_data(self):
        self.assertEqual(source_verdict_from_report(_report(level="info")).verdict, "no-data")
        self.assertEqual(source_verdict_from_report(_report(level="")).verdict, "no-data")

    def test_failure_status_is_no_data_and_failed(self):
        sv = source_verdict_from_report(_report(level="malicious", status="Failure"))
        self.assertEqual(sv.verdict, "no-data")
        self.assertTrue(sv.failed)

    def test_non_success_non_failure_is_no_data(self):
        sv = source_verdict_from_report(_report(status="InProgress"))
        self.assertEqual(sv.verdict, "no-data")
        self.assertFalse(sv.failed)

    def test_tier_and_weight_carried(self):
        sv = source_verdict_from_report(_report(name="VT", tier=1, weight=0.9))
        self.assertEqual((sv.name, sv.tier, sv.weight), ("VT", 1, 0.9))
        self.assertIsInstance(sv, SourceVerdict)

    def test_confidence_none_when_zero_or_none(self):
        self.assertIsNone(source_verdict_from_report(_report(confidence=0)).confidence)
        self.assertIsNone(source_verdict_from_report(_report(confidence=None)).confidence)

    def test_confidence_int_when_real_number(self):
        self.assertEqual(source_verdict_from_report(_report(confidence=71.0)).confidence, 71)

    def test_missing_tier_weight_default(self):
        report = _report()
        report.analyzer = SimpleNamespace(name="Bare")
        sv = source_verdict_from_report(report)
        self.assertEqual((sv.tier, sv.weight), (3, 0.2))
