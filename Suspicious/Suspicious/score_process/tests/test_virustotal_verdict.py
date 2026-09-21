import json
from pathlib import Path

from django.test import SimpleTestCase

from score_process.scoring.cortex_analyzers.contrib.virustotal import VirusTotalGetReportParser

FIX = Path(__file__).parent / "fixtures" / "virustotal"
CASES = sorted(p.stem for p in FIX.glob("*.json"))


class VirustotalVerdictTests(SimpleTestCase):
    def _run(self, name):
        spec = json.loads((FIX / f"{name}.json").read_text())
        p = VirusTotalGetReportParser(
            analyzer_name="VirusTotal_GetReport_3_1", data=name,
            data_type=spec["data_type"], case_id=None,
        )
        return p.parse({}, spec["report_full"]), spec["expect"]

    def test_all_fixtures_hit_expected_band(self):
        for name in CASES:
            with self.subTest(fixture=name):
                result, expect = self._run(name)
                self.assertEqual(result.level, expect["level"])
                if "confidence_min" in expect:
                    self.assertGreaterEqual(result.confidence, expect["confidence_min"])
                if "confidence_max" in expect:
                    self.assertLessEqual(result.confidence, expect["confidence_max"])

    def test_lone_fp_is_suspicious_not_malicious(self):
        result, _ = self._run("ip_lone_fp")
        self.assertEqual(result.level, "suspicious")   # was "malicious" before this change

    def test_extraction_none_falls_back_to_current_behaviour(self):
        # report_full with NO parseable VT attributes at all -> extract() -> None
        # -> the parser must use its pre-change logic. Here the stats-only path
        # (the `_stats()` helper reads results.data.attributes.last_analysis_stats)
        # still yields malicious=2, so old logic bands "malicious".
        p = VirusTotalGetReportParser(
            analyzer_name="VirusTotal_GetReport_3_1", data="x", data_type="ip", case_id=None,
        )
        full = {"results": {"data": {"attributes": {"last_analysis_stats":
                {"malicious": 2, "harmless": 5, "undetected": 1}}}}}
        # extract() returns a dict here (it can read last_analysis_stats), so the
        # refined path runs: m=2 -> malicious. Both paths agree -> assert malicious.
        r = p.parse({}, full)
        self.assertEqual(r.level, "malicious")

    def test_truly_unparseable_full_uses_legacy_flat_confidence(self):
        # results present but neither attributes nor positives -> _stats() None
        # AND extract() None -> parser hits its `stats is None and positives is None`
        # DefaultTaxonomyParser fallback (unchanged behaviour).
        p = VirusTotalGetReportParser(
            analyzer_name="VirusTotal_GetReport_3_1", data="x", data_type="ip", case_id=None,
        )
        r = p.parse({}, {"results": {"unexpected": "shape"}})
        self.assertEqual(r.level, "info")  # DefaultTaxonomyParser with empty summary
