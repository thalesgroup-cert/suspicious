import base64
from django.test import SimpleTestCase
from score_process.scoring.screenshots import lookyloo

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
B64 = base64.b64encode(PNG).decode()


class LookylooExtractTest(SimpleTestCase):
    def test_top_level_key(self):
        self.assertEqual(lookyloo.extract({"screenshot": B64}, "url", "http://x"), PNG)

    def test_wrapped_in_results(self):
        self.assertEqual(lookyloo.extract({"results": {"screenshot": B64}}, "url", "http://x"), PNG)

    def test_missing_key_returns_none(self):
        self.assertIsNone(lookyloo.extract({"lookyloo_url": "http://l/tree/1"}, "url", "http://x"))

    def test_not_a_png_returns_none(self):
        bad = base64.b64encode(b"<html>nope").decode()
        self.assertIsNone(lookyloo.extract({"screenshot": bad}, "url", "http://x"))

    def test_oversized_returns_none(self):
        big = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * (9 * 1024 * 1024)).decode()
        self.assertIsNone(lookyloo.extract({"screenshot": big}, "url", "http://x"))

    def test_non_dict_returns_none(self):
        self.assertIsNone(lookyloo.extract("boom", "url", "http://x"))
