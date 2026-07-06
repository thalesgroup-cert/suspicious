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
        kw.setdefault("analyzer_name", "Stub_1_0"); kw.setdefault("data", "x")
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
