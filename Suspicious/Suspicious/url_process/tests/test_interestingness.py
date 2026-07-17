from unittest import TestCase

from url_process.url_utils.url_planner import score_interestingness


class InterestingnessTests(TestCase):
    def test_raw_ip_host_scores_high(self):
        self.assertGreaterEqual(score_interestingness("http://203.0.113.5/login"), 40)

    def test_open_redirect_query_key_boosts(self):
        plain = score_interestingness("https://good.com/go?id=1")
        redir = score_interestingness("https://good.com/go?redirect=http://evil.com")
        self.assertGreater(redir, plain)

    def test_executable_in_path_boosts(self):
        self.assertGreaterEqual(score_interestingness("https://x.com/a/setup.exe"), 20)

    def test_punycode_boosts(self):
        self.assertGreaterEqual(score_interestingness("https://xn--pple-43d.com/login"), 30)

    def test_sender_domain_suppresses(self):
        other = score_interestingness("https://news.com/setup.exe", sender_domain="evil.com")
        same = score_interestingness("https://news.com/setup.exe", sender_domain="news.com")
        self.assertLess(same, other)

    def test_score_clamped_to_byte_range(self):
        s = score_interestingness("http://203.0.113.5:8443/x/y/z/setup.exe?redirect=1&next=2&a=3&b=4&c=5")
        self.assertGreaterEqual(s, 0)
        self.assertLessEqual(s, 255)

    def test_bare_host_is_low(self):
        self.assertLessEqual(score_interestingness("https://example.com/"), 0)
