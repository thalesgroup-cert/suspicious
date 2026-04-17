"""
Unit tests for SSRF protection in SubmitUrlSerializer.

_check_no_ssrf_ip() is tested directly — it uses only stdlib so needs
no stubs of its own.  We stub django.conf and rest_framework so that
api.serializers.submit can be imported without a running Django process.
"""
import sys
import unittest
from unittest.mock import MagicMock


def _setup_stubs():
    conf_stub = MagicMock()
    conf_stub.settings = MagicMock()
    conf_stub.settings.SUBMIT_CONTEXT_MAX_LENGTH = 2000
    conf_stub.settings.SUBMIT_OTHER_MAX_LENGTH = 4096
    conf_stub.settings.SUBMIT_FILE_MAX_BYTES = 25 * 1024 * 1024

    class _FakeValidationError(Exception):
        def __init__(self, detail):
            self.detail = detail
            super().__init__(detail)

    drf_serializers_stub = MagicMock()
    drf_serializers_stub.ValidationError = _FakeValidationError
    drf_serializers_stub.Serializer = object
    drf_serializers_stub.CharField = MagicMock(return_value=MagicMock())
    drf_serializers_stub.URLField = MagicMock(return_value=MagicMock())
    drf_serializers_stub.FileField = MagicMock(return_value=MagicMock())
    drf_serializers_stub.EmailField = MagicMock(return_value=MagicMock())

    sys.modules.setdefault("django",                   MagicMock())
    sys.modules.setdefault("django.conf",              conf_stub)
    sys.modules.setdefault("rest_framework",           MagicMock())
    sys.modules.setdefault("rest_framework.serializers", drf_serializers_stub)


_setup_stubs()

# Force a fresh import of the module so our stubs take effect.
# Also evict any stub that may have replaced 'api.serializers' as a flat
# MagicMock (e.g. from test_dashboard_cache) — we need it to resolve as a
# real package so that 'api.serializers.submit' can be imported.
for _k in list(sys.modules):
    if "api.serializers" in _k:
        del sys.modules[_k]

from api.serializers.submit import _check_no_ssrf_ip  # noqa: E402


class TestCheckNoSsrfIp(unittest.TestCase):

    # ── Blocked: loopback ───────────────────────────────────────────────────

    def test_blocks_ipv4_loopback(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://127.0.0.1/")

    def test_blocks_ipv6_loopback(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://[::1]/")

    # ── Blocked: RFC-1918 private ranges ───────────────────────────────────

    def test_blocks_10_dot(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://10.0.0.1/path")

    def test_blocks_172_16(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://172.16.0.1/")

    def test_blocks_172_31(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://172.31.255.255/")

    def test_blocks_192_168(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://192.168.1.1/")

    # ── Blocked: link-local (AWS/GCP metadata endpoint) ────────────────────

    def test_blocks_aws_metadata(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://169.254.169.254/latest/meta-data/")

    def test_blocks_link_local_ipv6(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://[fe80::1]/")

    # ── Blocked: unique-local IPv6 ─────────────────────────────────────────

    def test_blocks_ipv6_unique_local(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://[fc00::1]/")

    # ── Blocked: unspecified ───────────────────────────────────────────────

    def test_blocks_unspecified_ipv4(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://0.0.0.0/")

    # ── Allowed: public IPs ────────────────────────────────────────────────

    def test_allows_public_ip(self):
        # Should not raise
        _check_no_ssrf_ip("http://8.8.8.8/")

    def test_allows_public_ip_https(self):
        _check_no_ssrf_ip("https://1.1.1.1/")

    # ── Allowed: domain names (not resolved in phase 1) ───────────────────

    def test_allows_domain_name(self):
        _check_no_ssrf_ip("http://example.com/")

    def test_allows_internal_domain(self):
        # Domain names pass through — DNS resolution is phase 2
        _check_no_ssrf_ip("https://suspicious.corp.thales/api/")

    # ── Edge cases ─────────────────────────────────────────────────────────

    def test_empty_hostname_does_not_raise(self):
        # URLField already rejects these; helper should not crash
        _check_no_ssrf_ip("http:///path")

    def test_error_message_is_vague(self):
        try:
            _check_no_ssrf_ip("http://127.0.0.1/")
            self.fail("Expected ValueError")
        except ValueError as e:
            self.assertIn("private or reserved", str(e))
            # Must NOT reveal internal topology details
            self.assertNotIn("127.0.0.1", str(e))


if __name__ == "__main__":
    unittest.main()
