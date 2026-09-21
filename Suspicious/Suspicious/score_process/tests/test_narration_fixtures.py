import ipaddress
import json
import re
from pathlib import Path

from django.test import SimpleTestCase

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "narration"
FIXTURE_NAMES = [
    "mail_safe.json",
    "mail_suspicious.json",
    "mail_dangerous.json",
    "ioc_safe.json",
    "ioc_suspicious_multi.json",
    "ioc_dangerous_single.json",
]

_DOC_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
_RESERVED_DOMAIN_SUFFIXES = (".example.com", ".example.net", ".example.org")
# Matches a dotted hostname ending in .com/.net/.org, whether it's a bare
# value ("docs.example.com") or embedded in a URL ("hxxp://foo.example.com/x").
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+(?:com|net|org)\b")


def _looks_like_ipv4(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _iter_string_values(report_full: dict):
    """Yield every string value in a report_full dict, including strings
    nested one level inside list values (e.g. threat_labels, events)."""
    for value in report_full.values():
        if isinstance(value, str):
            yield value
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    yield item


class FixtureShapeTest(SimpleTestCase):
    def test_all_fixtures_exist_and_have_required_shape(self):
        for name in FIXTURE_NAMES:
            path = FIXTURES_DIR / name
            with self.subTest(fixture=name):
                self.assertTrue(path.exists(), f"missing fixture {path}")
                data = json.loads(path.read_text())
                self.assertIn("verdict", data)
                verdict = data["verdict"]
                for key in ("band", "score", "confidence", "rule"):
                    self.assertIn(key, verdict)
                self.assertIn(verdict["band"], ("Safe", "Suspicious", "Dangerous", "Inconclusive"))
                self.assertIn("analyzer_reports", data)
                for report in data["analyzer_reports"]:
                    self.assertIn("analyzer", report)
                    self.assertIn("report_full", report)
                    for value in _iter_string_values(report["report_full"]):
                        if _looks_like_ipv4(value):
                            self.assertTrue(
                                any(ipaddress.ip_address(value) in net for net in _DOC_RANGES),
                                f"{name=} {value=} is not an RFC 5737 documentation-range IP",
                            )
                        for domain in _DOMAIN_RE.findall(value):
                            self.assertTrue(
                                domain.endswith(_RESERVED_DOMAIN_SUFFIXES),
                                f"{name=} {domain=} is not a subdomain of example.com/.net/.org",
                            )
