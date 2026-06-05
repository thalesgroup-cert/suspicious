"""SSRF guard tests for URL submission.

Covers `_check_no_ssrf_ip` / `SubmitUrlSerializer.validate_url`:
IP literals, ambiguous numeric encodings, IPv4-mapped IPv6, and
DNS names that resolve to private/reserved addresses.
"""
from django.test import SimpleTestCase

from api.serializers.submit import SubmitUrlSerializer, _check_no_ssrf_ip


class CheckNoSsrfIpTests(SimpleTestCase):
    def assertBlocked(self, url):
        with self.assertRaises(ValueError, msg=f"{url} should be blocked"):
            _check_no_ssrf_ip(url)

    def assertAllowed(self, url):
        try:
            _check_no_ssrf_ip(url)
        except ValueError as exc:  # pragma: no cover - failure path
            self.fail(f"{url} should be allowed, raised: {exc}")

    def test_public_ip_literal_allowed(self):
        self.assertAllowed("http://8.8.8.8/")
        self.assertAllowed("https://1.1.1.1/path")

    def test_loopback_and_private_literals_blocked(self):
        for url in (
            "http://127.0.0.1/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://169.254.169.254/latest/meta-data/",  # cloud metadata
            "http://[::1]/",                              # IPv6 loopback
            "http://[fe80::1]/",                          # IPv6 link-local
        ):
            self.assertBlocked(url)

    def test_ipv4_mapped_ipv6_loopback_blocked(self):
        self.assertBlocked("http://[::ffff:127.0.0.1]/")

    def test_numeric_encodings_blocked(self):
        # All of these resolve to 127.0.0.1 in common HTTP clients.
        self.assertBlocked("http://2130706433/")    # decimal
        self.assertBlocked("http://0x7f000001/")    # hex
        self.assertBlocked("http://0177.0.0.1/")    # octal first octet

    def test_domain_resolving_to_loopback_blocked(self):
        # localhost resolves to 127.0.0.1 / ::1 deterministically.
        self.assertBlocked("http://localhost/")
        self.assertBlocked("http://localhost:8080/admin")

    def test_unresolvable_domain_passes(self):
        # Fails closed at fetch time; the guard does not raise on NXDOMAIN.
        self.assertAllowed("http://no-such-host.invalid/")

    def test_no_hostname_passes(self):
        self.assertAllowed("not-a-url")


class SubmitUrlSerializerTests(SimpleTestCase):
    def test_rejects_loopback(self):
        s = SubmitUrlSerializer(data={"url": "http://127.0.0.1/"})
        self.assertFalse(s.is_valid())
        self.assertIn("url", s.errors)

    def test_rejects_decimal_ip(self):
        s = SubmitUrlSerializer(data={"url": "http://2130706433/"})
        self.assertFalse(s.is_valid())

    def test_accepts_public_ip(self):
        s = SubmitUrlSerializer(data={"url": "http://8.8.8.8/"})
        self.assertTrue(s.is_valid(), s.errors)

    def test_bare_domain_gets_scheme_then_checked(self):
        # Bare private host without scheme is still blocked.
        s = SubmitUrlSerializer(data={"url": "localhost"})
        self.assertFalse(s.is_valid())
