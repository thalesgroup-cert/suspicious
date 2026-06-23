import unittest

from url_process.url_utils.url_planner import (
    DEFAULT_SHORTENER_DOMAINS,
    DEFAULT_SUSPICIOUS_TLDS,
)


class ConfigDefaultsTest(unittest.TestCase):
    def test_builtin_denylists_present(self):
        assert "bit.ly" in DEFAULT_SHORTENER_DOMAINS
        assert "zip" in DEFAULT_SUSPICIOUS_TLDS
