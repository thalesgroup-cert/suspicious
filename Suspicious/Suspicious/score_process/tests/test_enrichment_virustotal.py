import json
from pathlib import Path

from django.test import SimpleTestCase

from score_process.scoring.enrichment.registry import enrich
from score_process.scoring.enrichment.virustotal import extract

FIX = Path(__file__).parent / "fixtures" / "virustotal"


def _full(name):
    return json.loads((FIX / f"{name}.json").read_text())["report_full"]


class VirustotalExtractTests(SimpleTestCase):
    def test_none_when_no_vt_attributes(self):
        self.assertIsNone(extract({"results": {"foo": 1}}, "ip"))
        self.assertIsNone(extract(None, "ip"))
        self.assertIsNone(extract("garbage", "hash"))

    def test_ip_extraction(self):
        e = extract(_full("ip_lone_fp"), "ip", value="8.8.8.8")
        self.assertEqual(e["source"], "virustotal")
        self.assertEqual(e["malicious_count"], 1)
        self.assertGreaterEqual(e["total"], 80)
        self.assertEqual(e["as_owner"], "Google LLC")
        self.assertEqual(e["country"], "US")
        self.assertTrue(e["vt_link"].endswith("/ip-address/8.8.8.8"))
        # vendors sorted flagging-first
        self.assertEqual(e["vendors"][0]["category"], "malicious")

    def test_hash_threat_classification(self):
        e = extract(_full("hash_emotet"), "hash", value="a" * 64)
        self.assertEqual(e["threat_category"], "trojan")
        self.assertIn("emotet", e["threat_label"])
        self.assertIn("invoice", e["meaningful_name"].lower())
        self.assertLessEqual(len(e["names"]), 10)

    def test_dates_are_iso_utc(self):
        e = extract(_full("hash_emotet"), "hash", value="a" * 64)
        self.assertRegex(e["first_seen"], r"^\d{4}-\d\d-\d\dT.*Z$")

    def test_legacy_positives_shape(self):
        e = extract(_full("legacy_positives"), "url", value="http://x.test")
        self.assertEqual(e["malicious_count"], 3)
        self.assertEqual(e["total"], 70)
        self.assertTrue(all("category" in v for v in e["vendors"]))

    def test_partial_dict_on_malformed_numeric(self):
        full = _full("ip_lone_fp")
        full["results"]["data"]["attributes"]["last_analysis_stats"]["malicious"] = "not-a-number"
        e = extract(full, "ip", value="8.8.8.8")
        self.assertIsNotNone(e)
        self.assertEqual(e["source"], "virustotal")
        self.assertEqual(e["as_owner"], "Google LLC")


class _StubReport:
    url_id = domain_id = hash_id = ip_id = file_id = mail_id = None
    mail_body_id = mail_header_id = None
    type = "ip"

    def __init__(self, analyzer_name, report_full={"results": {"positives": 1, "total": 10, "scans": {}}}):
        self.analyzer = type("A", (), {"name": analyzer_name})()
        self._report_full = report_full

    @property
    def report_full(self):
        return self._report_full


class RegistryEnrichTests(SimpleTestCase):
    def test_virustotal_analyzer_matched(self):
        e = enrich(_StubReport("VirusTotal_GetReport_3_1"))
        self.assertEqual(e["source"], "virustotal")

    def test_gti_analyzer_not_matched(self):
        self.assertIsNone(enrich(_StubReport("GoogleThreatIntelligence_GetReport_1_0")))

    def test_raising_report_full_swallowed(self):
        class Boom(_StubReport):
            @property
            def report_full(self):
                raise RuntimeError("boom")

        self.assertIsNone(enrich(Boom("VirusTotal_GetReport_3_1")))
