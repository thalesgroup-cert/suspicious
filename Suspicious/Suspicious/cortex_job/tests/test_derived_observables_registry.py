from unittest import TestCase

from cortex_job.cortex_utils.derived_observables import EXTRACTORS


class UnshortenExtractorTests(TestCase):
    fn = staticmethod(EXTRACTORS["UnshortenLink_1_2"])

    def test_found_true_yields_the_url(self):
        self.assertEqual(self.fn({"found": True, "url": "https://evil.example/x"}),
                         [("https://evil.example/x", "url")])

    def test_found_false_yields_nothing(self):
        self.assertEqual(self.fn({"found": False, "url": None}), [])

    def test_garbage_yields_nothing(self):
        for bad in [{}, None, {"found": True}, {"found": True, "url": ""}, "nope"]:
            self.assertEqual(self.fn(bad), [])


class QrDecodeExtractorTests(TestCase):
    fn = staticmethod(EXTRACTORS["QrDecode_1_0"])

    def _full(self, *entries):
        return {"results_list": [{"results": e} for e in entries],
                "stats": {"total_qr_codes": len(entries)}}

    def test_url_qr_yields_url(self):
        full = self._full({"data": "https://evil.example/q", "data_type": "url"})
        self.assertEqual(self.fn(full), [("https://evil.example/q", "url")])

    def test_multiple_and_mixed_types(self):
        full = self._full(
            {"data": "https://a.example", "data_type": "url"},
            {"data": "1.2.3.4", "data_type": "ip"},
            {"data": "hello world", "data_type": "other"},   # dropped
        )
        self.assertEqual(self.fn(full),
                         [("https://a.example", "url"), ("1.2.3.4", "ip")])

    def test_garbage_yields_nothing(self):
        for bad in [{}, None, {"results_list": "x"}, {"results_list": [{}]},
                    {"results_list": [{"results": {"data": "", "data_type": "url"}}]}]:
            self.assertEqual(self.fn(bad), [])
