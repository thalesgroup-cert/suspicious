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
