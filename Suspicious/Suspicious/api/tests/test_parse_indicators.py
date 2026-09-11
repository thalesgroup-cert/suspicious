from django.test import SimpleTestCase
from api.utils.indicators import parse_indicators


class ParseIndicatorsTests(SimpleTestCase):
    def test_splits_on_newline_comma_space(self):
        out = parse_indicators("8.8.8.8, 1.1.1.1\nhttp://a.test  9.9.9.9")
        self.assertEqual([p.value for p in out], ["8.8.8.8", "1.1.1.1", "http://a.test", "9.9.9.9"])

    def test_refangs(self):
        out = parse_indicators("hxxp://evil[.]com  1[.]2[.]3[.]4")
        self.assertEqual(out[0].value, "http://evil.com")
        self.assertEqual(out[0].type, "url")
        self.assertEqual(out[1].value, "1.2.3.4")
        self.assertEqual(out[1].type, "ip")

    def test_type_detection(self):
        types = {p.value: p.type for p in parse_indicators(
            "8.8.8.8\n" + "a" * 64 + "\nexample.com\nhttp://example.com/x"
        )}
        self.assertEqual(types["8.8.8.8"], "ip")
        self.assertEqual(types["a" * 64], "hash")
        self.assertEqual(types["example.com"], "domain")
        self.assertEqual(types["http://example.com/x"], "url")

    def test_non_domain_shapes_are_unclassified(self):
        # parity with the frontend preview regex — these are NOT domains
        types = {p.value: p.type for p in parse_indicators(
            "user@example.com\n8.8.8.8:80\n1.2.3.4.5"
        )}
        self.assertIsNone(types["user@example.com"])
        self.assertIsNone(types["8.8.8.8:80"])
        self.assertIsNone(types["1.2.3.4.5"])

    def test_dedupe_preserves_order(self):
        out = parse_indicators("8.8.8.8\n8.8.8.8\n1.1.1.1")
        self.assertEqual([p.value for p in out], ["8.8.8.8", "1.1.1.1"])

    def test_unparseable_line_kept_with_none_type(self):
        out = parse_indicators("not an indicator !!!")
        self.assertIsNone(out[0].type)
