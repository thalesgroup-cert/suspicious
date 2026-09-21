from unittest import TestCase

from url_process.url_utils.url_unwrap import unwrap_url


class UnwrapUrlTests(TestCase):
    def test_safelinks_returns_the_wrapped_url(self):
        w = ("https://nam12.safelinks.protection.outlook.com/?url="
             "https%3A%2F%2Fevil.example%2Fphish&data=05%7C01%7C&sdata=abc&reserved=0")
        self.assertEqual(unwrap_url(w), ["https://evil.example/phish"])

    def test_urldefense_v2_decodes_dash_underscore_encoding(self):
        # Proofpoint v2: '-' -> '%', '_' -> '/' in the `u` param, then unquote.
        w = ("https://urldefense.proofpoint.com/v2/url?u=http-3A__evil.example_a-2Db"
             "&d=DwMFaQ&c=abc&r=def&m=ghi&s=jkl&e=")
        self.assertEqual(unwrap_url(w), ["http://evil.example/a-b"])

    def test_urldefense_v3_takes_literal_between_markers(self):
        w = ("https://urldefense.com/v3/__https://evil.example/phish?x=1__;Iw!!"
             "AbC123$")
        self.assertEqual(unwrap_url(w), ["https://evil.example/phish?x=1"])

    def test_plain_url_is_not_a_wrapper(self):
        self.assertEqual(unwrap_url("https://example.com/newsletter?utm=1"), [])

    def test_safelinks_without_url_param_yields_nothing(self):
        self.assertEqual(
            unwrap_url("https://x.safelinks.protection.outlook.com/?data=05"), [])

    def test_non_http_wrapped_value_is_rejected(self):
        w = "https://x.safelinks.protection.outlook.com/?url=javascript%3Aalert(1)"
        self.assertEqual(unwrap_url(w), [])

    def test_nested_safelinks_around_urldefense_unwraps_both_hops(self):
        inner = "https://urldefense.com/v3/__https://evil.example/x__;!!a$"
        from urllib.parse import quote
        w = ("https://x.safelinks.protection.outlook.com/?url=" + quote(inner, safe=""))
        self.assertEqual(unwrap_url(w), [inner, "https://evil.example/x"])

    def test_garbage_input_returns_empty_not_raise(self):
        for bad in ["", "not a url", "http://", "://///"]:
            self.assertEqual(unwrap_url(bad), [])
