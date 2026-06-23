from unittest import TestCase
from url_process.url_utils.url_planner import canonical_key


class CanonicalKeyTests(TestCase):

    def test_query_values_ignored_keys_kept(self):
        a = canonical_key("https://x.com/p?id=1&t=aaa")
        b = canonical_key("https://x.com/p?id=2&t=bbb")
        self.assertEqual(a, b)

    def test_new_query_key_is_distinct(self):
        base = canonical_key("https://x.com/p?id=1")
        redirect = canonical_key("https://x.com/p?redirect=evil")
        self.assertNotEqual(base, redirect)

    def test_query_key_order_normalised(self):
        self.assertEqual(
            canonical_key("https://x.com/p?b=1&a=2"),
            canonical_key("https://x.com/p?a=9&b=8")
        )

    def test_host_lowercased_and_www_stripped(self):
        self.assertEqual(
            canonical_key("https://WWW.X.com/p"),
            canonical_key("https://x.com/p")
        )

    def test_fragment_dropped(self):
        self.assertEqual(
            canonical_key("https://x.com/p#frag"),
            canonical_key("https://x.com/p")
        )

    def test_distinct_paths_stay_distinct(self):
        self.assertNotEqual(
            canonical_key("https://x.com/a"),
            canonical_key("https://x.com/b")
        )

    def test_scheme_preserved(self):
        self.assertNotEqual(
            canonical_key("http://x.com/p"),
            canonical_key("https://x.com/p")
        )

    def test_missing_scheme_defaults_to_http(self):
        # bare host already normalised upstream, but be defensive
        self.assertEqual(
            canonical_key("x.com/p"),
            canonical_key("http://x.com/p")
        )
