# score_process/tests/test_analyzer_parsers.py
from django.test import SimpleTestCase
from score_process.scoring.cortex_analyzers.result import (
    AnalyzerResult, AllowListResult, PENDING,
)

class ResultModuleTests(SimpleTestCase):
    def test_pending_is_singleton_sentinel(self):
        from score_process.scoring.cortex_analyzers.result import PENDING as P2
        self.assertIs(PENDING, P2)

    def test_analyzer_result_coerces_data_to_str(self):
        r = AnalyzerResult(analyzer_name="x", data=123, score=0,
                           confidence=0, category="c", level="info", details={})
        self.assertEqual(r.data, "123")

    def test_allow_list_defaults_none(self):
        self.assertIsNone(AllowListResult().DomainAllowList)


import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "cortex"

def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())

class FixtureCorpusTests(SimpleTestCase):
    def test_ai_mail_fixture_has_classification(self):
        f = load_fixture("ai_mail")
        self.assertIn("classification", f["summary"])
        self.assertIn("malscore", f["summary"])

    def test_fileinfo_fixture_has_taxonomies(self):
        self.assertIn("taxonomies", load_fixture("fileinfo")["summary"])

    def test_pending_fixture_is_ongoing(self):
        self.assertEqual(load_fixture("pending")["summary"], {"ongoing": "analysis"})


from unittest.mock import patch
from score_process.scoring.cortex_analyzers.base import (
    AnalyzerParser, AnalyzerManifest, is_pending,
)


class _StubParser(AnalyzerParser):
    manifest = AnalyzerManifest(name="stub", cortex_names=("Stub_1_0",))
    def parse(self, summary, full):
        return AnalyzerResult(analyzer_name=self.analyzer_name, data=self.data,
                              score=9, confidence=90, category="c", level="malicious",
                              details={})

class BaseParserTests(SimpleTestCase):
    def _mk(self, **kw):
        kw.setdefault("analyzer_name", "Stub_1_0")
        kw.setdefault("data", "x")
        kw.setdefault("data_type", "url")
        return _StubParser(**kw)

    def test_is_pending_ongoing(self):
        self.assertTrue(is_pending({"ongoing": "analysis"}, {"ongoing": "analysis"}))

    def test_is_pending_empty(self):
        self.assertTrue(is_pending(None, None))

    def test_is_pending_status(self):
        self.assertTrue(is_pending({"taxonomies": []}, {}, status="InProgress"))

    def test_run_returns_pending_for_ongoing(self):
        self.assertIs(self._mk().run({"ongoing": "analysis"}, {"ongoing": "analysis"}), PENDING)

    @patch("score_process.scoring.cortex_analyzers.base.check_allow_list")
    def test_run_allow_list_short_circuits_safe(self, m_allow):
        from score_process.scoring.cortex_analyzers.result import AllowListResult
        m_allow.return_value = AllowListResult(DomainAllowList="Safe DW triggered")
        r = self._mk(data_type="domain").run({"taxonomies": []}, {})
        self.assertEqual((r.score, r.confidence, r.level), (0, 100, "safe"))

    @patch("score_process.scoring.cortex_analyzers.base.check_allow_list")
    def test_run_calls_parse_when_clean(self, m_allow):
        from score_process.scoring.cortex_analyzers.result import AllowListResult
        m_allow.return_value = AllowListResult()
        r = self._mk().run({"taxonomies": [{"level": "malicious"}]}, {})
        self.assertEqual(r.level, "malicious")


from score_process.scoring.cortex_analyzers.default import (
    DefaultTaxonomyParser, get_level_score_confidence,
)

class DefaultParserTests(SimpleTestCase):
    def _mk(self, data="x", data_type="file"):
        return DefaultTaxonomyParser(analyzer_name="FileInfo_8_0", data=data,
                                     data_type=data_type)

    def test_level_score_confidence(self):
        self.assertEqual(get_level_score_confidence("malicious"), (10, 100))
        self.assertEqual(get_level_score_confidence("safe"), (0, 100))
        self.assertEqual(get_level_score_confidence("nonsense"), (0, 0))

    def test_fileinfo_fixture_parses_info(self):
        f = load_fixture("fileinfo")
        r = self._mk().parse(f["summary"], f["full"])
        self.assertEqual(r.level, "info")
        self.assertIn("TXT", r.category)

    def test_taxonomy_raises_to_highest_severity(self):
        summary = {"taxonomies": [
            {"level": "info", "value": "a", "predicate": "p1"},
            {"level": "malicious", "value": "b", "predicate": "p2"},
        ]}
        r = self._mk().parse(summary, None)
        self.assertEqual(r.level, "malicious")
        self.assertEqual((r.score, r.confidence), (10, 100))

    def test_safe_only_taxonomy_scores_safe(self):
        # Regression: a lone `safe` taxonomy (e.g. GoogleSafebrowsing "0 match")
        # must yield safe/0, not be floored to the info default.
        summary = {"taxonomies": [
            {"level": "safe", "value": "0 match", "predicate": "Safebrowsing"},
        ]}
        r = self._mk().parse(summary, None)
        self.assertEqual(r.level, "safe")
        self.assertEqual((r.score, r.confidence), (0, 100))

    def test_safe_and_info_taxonomy_takes_info(self):
        summary = {"taxonomies": [
            {"level": "safe", "value": "a", "predicate": "p1"},
            {"level": "info", "value": "b", "predicate": "p2"},
        ]}
        self.assertEqual(self._mk().parse(summary, None).level, "info")


class AiMailParserTests(SimpleTestCase):
    def _mk(self):
        from score_process.scoring.cortex_analyzers.contrib.ai_mail import AiMailParser
        return AiMailParser(analyzer_name="AI_Mail_Analyzer_2_0", data="mail.eml",
                            data_type="file", case_id=1)

    @patch("score_process.scoring.cortex_analyzers.contrib.ai_mail.AiMailParser._run_campaign")
    def test_safe_mail_score_mapping(self, m_campaign):
        f = load_fixture("ai_mail")   # classification SAFE, malscore 1.52, confidence 0.848
        r = self._mk().parse(f["summary"], f["full"])
        self.assertEqual(r.level, "safe")
        self.assertEqual(r.score, 2)          # round(1.52)
        self.assertEqual(r.confidence, 85)    # round(0.848 * 100)
        m_campaign.assert_called_once()       # side-effects invoked but stubbed

    @patch("score_process.scoring.cortex_analyzers.contrib.ai_mail.AiMailParser._run_campaign")
    def test_manifest_matches_versioned_and_bare(self, _m):
        names = self._mk().manifest.cortex_names
        self.assertIn("AI_Mail_Analyzer", names)
        self.assertIn("AI_Mail_Analyzer_2_0", names)


from types import SimpleNamespace
from score_process.scoring.cortex_analyzers.registry import AnalyzerParserRegistry
from score_process.scoring.cortex_analyzers.contrib.ai_mail import AiMailParser

class RegistryTests(SimpleTestCase):
    def setUp(self):
        self.reg = AnalyzerParserRegistry()
        self.reg.discover()

    def test_resolve_by_name(self):
        a = SimpleNamespace(name="AI_Mail_Analyzer_2_0", analyzer_cortex_id="zzz")
        self.assertIs(self.reg.resolve(a), AiMailParser)

    def test_resolve_by_cortex_id(self):
        a = SimpleNamespace(name="whatever", analyzer_cortex_id="AI_Mail_Analyzer")
        self.assertIs(self.reg.resolve(a), AiMailParser)

    def test_unknown_falls_back_to_default(self):
        a = SimpleNamespace(name="GoogleDNS_resolve_1_0_0", analyzer_cortex_id="gdns")
        self.assertIs(self.reg.resolve(a), DefaultTaxonomyParser)


from unittest.mock import MagicMock
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

class ReportsRewireTests(SimpleTestCase):
    def _report(self, summary, full, status="Success"):
        r = MagicMock()
        r.report_summary, r.report_full, r.status, r.type = summary, full, status, "hash"
        r.analyzer.name = "CIRCLHashlookup_1_1"
        r.analyzer.analyzer_cortex_id = "circl"
        return r

    def test_pending_report_not_saved(self):
        r = self._report({"ongoing": "analysis"}, {"ongoing": "analysis"})
        CortexAnalyzerReports.create_and_save_report(r, "abc123", case_id=1)
        r.save.assert_not_called()

    def test_success_report_saved_with_scores(self):
        r = self._report({"taxonomies": [{"level": "info", "value": "TXT",
                                          "predicate": "Filetype"}]}, {})
        CortexAnalyzerReports.create_and_save_report(r, "abc123", case_id=1)
        r.save.assert_called_once()
        self.assertEqual(r.level, "info")


from score_process.scoring.cortex_analyzers.contrib.zscaler import ZscalerParser

class ZscalerParserTests(SimpleTestCase):
    def _run(self, fixture):
        f = load_fixture(fixture)
        p = ZscalerParser(analyzer_name="Zscaler_1_0", data="http://x", data_type="url")
        return p.parse(f["summary"], f["full"])

    def test_benign_is_info(self):
        r = self._run("zscaler")
        self.assertEqual(r.level, "info")
        self.assertEqual(r.score, 5)
        self.assertIn("CORPORATE_MARKETING", r.category)

    def test_security_alert_is_malicious(self):
        r = self._run("zscaler_alert")
        self.assertEqual(r.level, "malicious")
        self.assertEqual(r.score, 10)
        self.assertEqual(r.confidence, 100)
        self.assertIn("PHISHING", r.category)


from score_process.scoring.cortex_analyzers.contrib.virustotal import VirusTotalGetReportParser

class VirusTotalParserTests(SimpleTestCase):
    def _run(self, fixture):
        f = load_fixture(fixture)
        p = VirusTotalGetReportParser(analyzer_name="VirusTotal_GetReport_3_1", data="abc123", data_type="hash")
        return p.parse(f["summary"], f["full"])

    def test_clean_is_safe(self):
        r = self._run("virustotal_clean")
        self.assertEqual(r.level, "safe")
        self.assertEqual(r.score, 0)
        self.assertIn("0/", " ".join(r.category) if isinstance(r.category, list) else r.category)

    def test_malicious_stats(self):
        r = self._run("virustotal_malicious")
        self.assertEqual(r.level, "malicious")
        self.assertEqual(r.score, 10)
        self.assertEqual(r.details["last_analysis_stats"]["malicious"], 5)

    def test_no_stats_falls_back_to_taxonomy(self):
        p = VirusTotalGetReportParser(analyzer_name="VirusTotal_GetReport_3_1", data="x", data_type="hash")
        r = p.parse({"taxonomies": [{"level": "suspicious", "value": "VT"}]}, {"message": "no report"})
        self.assertEqual(r.level, "suspicious")

    def test_non_dict_attributes_falls_back(self):
        p = VirusTotalGetReportParser(analyzer_name="VirusTotal_GetReport_3_1", data="x", data_type="hash")
        r = p.parse({"taxonomies": [{"level": "info", "value": "VT"}]},
                    {"results": {"data": {"attributes": None}}})
        self.assertEqual(r.level, "info")  # no crash; delegated to taxonomy
