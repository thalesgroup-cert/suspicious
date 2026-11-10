from django.test import SimpleTestCase

from api.utils.report_facts import get_path, iso_utc, vt_facts

VT_DOMAIN = {"results": {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 2, "suspicious": 1, "undetected": 80, "harmless": 8, "timeout": 0},
    "last_analysis_results": {"EngineA": {"category": "malicious", "result": "phishing"},
                              "EngineB": {"category": "suspicious", "result": None},
                              "EngineC": {"category": "harmless", "result": "clean"}},
    "registrar": "Example Registrar LLC", "creation_date": 1790000000, "last_update_date": 1790500000,
    "rdap": {"entities": [{"roles": ["registrant"], "vcard_array": [
                 {"name": "fn", "values": ["Jane Doe"]}, {"name": "email", "values": ["abuse@registrar.test"]},
                 {"name": "tel", "values": ["+1.5550100"]}]}],
             "nameservers": [{"ldh_name": "ns1.example.test"}, {"ldh_name": "ns2.example.test"}],
             "status": ["client transfer prohibited"],
             "events": [{"event_action": "expiration", "event_date": "2027-09-27T22:06:27Z"}]},
    "categories": {"VendorX": "phishing"}, "popularity_ranks": {"Cisco Umbrella": {"rank": 812, "timestamp": 1}},
    "last_dns_records": [{"type": "A", "value": "203.0.113.10"}, {"type": "AAAA", "value": "2001:db8::1"},
                         {"type": "MX", "value": "mx.example.test"}],
}}}}

VT_IP = {"results": {"data": {"attributes": {
    "asn": 64500, "as_owner": "Example Net", "network": "203.0.113.0/24",
    "regional_internet_registry": "RIPE NCC", "country": "NL", "continent": "EU",
    "reputation": -5, "tags": ["tor"], "total_votes": {"harmless": 1, "malicious": 4},
    "threat_severity": {"threat_severity_level": "HIGH"},
}}}}

VT_URL = {"results": {"attributes": {
    "last_final_url": "https://login-example.test/a", "title": "Sign in",
    "last_http_response_code": 200, "threat_names": ["Phishing.Test"],
    "identified_brands": ["ExampleBank", {"name": "ExampleBank"}],
    "first_submission_date": 1790000000, "times_submitted": 7, "outgoing_links": ["a", "b", "c"],
    "categories": {"VendorX": "phishing"},
}}}

VT_HASH = {"results": {"data": {"attributes": {
    "first_submission_date": 1790000000, "last_submission_date": 1790500000,
    "last_analysis_date": 1790500000, "meaningful_name": "invoice.exe", "names": ["invoice.exe", "a.bin"],
    "type_description": "Win32 EXE", "size": 1024, "md5": "m" * 32, "sha1": "s" * 40, "sha256": "h" * 64,
    "sandbox_verdicts": {"Zenbox": {"category": "malicious", "malware_names": ["x"]}},
    "popular_threat_classification": {"suggested_threat_label": "trojan.test"},
}}}}


class VtFactsTests(SimpleTestCase):
    def test_domain_facts_from_report_full(self):
        f = vt_facts(None, VT_DOMAIN, "domain", "login-example.test")
        self.assertEqual(f.detections, (2, 1, 91))
        self.assertEqual(f.flagged_vendors, [("EngineA", "phishing"), ("EngineB", None)])
        self.assertEqual(f.registrar, "Example Registrar LLC")
        self.assertEqual(f.created, "2026-09-21T14:13:20Z")
        self.assertEqual(f.registrant, "Jane Doe")
        self.assertEqual(f.contact_emails, ["abuse@registrar.test"])
        self.assertEqual(f.contact_phones, ["+1.5550100"])
        self.assertEqual(f.name_servers, ["ns1.example.test", "ns2.example.test"])
        self.assertEqual(f.statuses, ["client transfer prohibited"])
        self.assertEqual(f.expires, "2027-09-27T22:06:27Z")
        self.assertEqual(f.resolved_ips, ["203.0.113.10", "2001:db8::1"])
        self.assertEqual(f.popularity_ranks, {"Cisco Umbrella": 812})
        self.assertEqual(f.categories, {"VendorX": "phishing"})
        self.assertEqual(f.vt_link, "https://www.virustotal.com/gui/domain/login-example.test")

    def test_enrichment_wins_over_report_full(self):
        f = vt_facts({"malicious_count": 42, "total": 70, "suspicious_count": 0, "as_owner": "Evil Hosting LLC"},
                     {"results": {"data": {"attributes": {"as_owner": "Other", "country": "NL"}}}},
                     "ip", "203.0.113.7")
        self.assertEqual(f.detections, (42, 0, 70))
        self.assertEqual(f.as_owner, "Evil Hosting LLC")
        self.assertEqual(f.country, "NL")

    def test_ip_fields(self):
        f = vt_facts(None, VT_IP, "ip", "203.0.113.7")
        self.assertEqual((f.asn, f.network, f.rir, f.continent), (64500, "203.0.113.0/24", "RIPE NCC", "EU"))
        self.assertEqual((f.reputation, f.tags, f.total_votes), (-5, ["tor"], {"harmless": 1, "malicious": 4}))
        self.assertEqual(f.threat_severity, "HIGH")

    def test_url_fields(self):
        f = vt_facts(None, VT_URL, "url", "https://login-example.test/a")
        self.assertEqual((f.final_url, f.title, f.http_code), ("https://login-example.test/a", "Sign in", 200))
        self.assertEqual(f.brands, ["ExampleBank"])
        self.assertEqual((f.outgoing_links, f.times_submitted), (3, 7))
        self.assertEqual(f.threat_names, ["Phishing.Test"])
        self.assertEqual(f.first_submission, "2026-09-21T14:13:20Z")

    def test_hash_fields(self):
        f = vt_facts(None, VT_HASH, "hash", "h" * 64)
        self.assertEqual((f.md5, f.sha256, f.size), ("m" * 32, "h" * 64, 1024))
        self.assertEqual(f.sandbox_verdicts, [("Zenbox", "malicious")])
        self.assertEqual(f.threat_label, "trojan.test")
        self.assertEqual(f.last_submission, "2026-09-27T09:06:40Z")
        self.assertEqual(f.last_analysis, "2026-09-27T09:06:40Z")
        self.assertEqual(f.names, ["invoice.exe", "a.bin"])

    def test_whois_text_fills_gaps(self):
        rf = {"results": {"data": {"attributes": {"whois": (
            "Registrar: Whois Reg\nCreation Date: 2026-01-02T03:04:05Z\n"
            "Updated Date: 2026-02-02T00:00:00Z\nRegistry Expiry Date: 2027-01-02T03:04:05Z\n")}}}}
        f = vt_facts(None, rf, "domain", "x.test")
        self.assertEqual((f.registrar, f.created), ("Whois Reg", "2026-01-02T03:04:05Z"))
        self.assertEqual((f.updated, f.expires), ("2026-02-02T00:00:00Z", "2027-01-02T03:04:05Z"))

    def test_wrong_types_and_nulls_are_ignored(self):
        bad = {"results": {"data": {"attributes": {
            "last_analysis_stats": None, "last_analysis_results": [], "rdap": "text",
            "popularity_ranks": [], "asn": "AS64500", "last_dns_records": {"A": "x"},
            "creation_date": "soon", "categories": None, "identified_brands": [None, 3]}}}}
        for dt in ("ip", "domain", "url", "hash"):
            f = vt_facts(None, bad, dt, "x")
            self.assertIsNone(f.detections)
            self.assertIsNone(f.asn)
            self.assertIsNone(f.created)
            self.assertEqual((f.resolved_ips, f.popularity_ranks, f.brands), ([], {}, []))

    def test_no_vt_payload_gives_empty_facts_but_link(self):
        f = vt_facts(None, {"ongoing": True}, "ip", "203.0.113.7")
        self.assertIsNone(f.detections)
        self.assertEqual(f.vt_link, "https://www.virustotal.com/gui/ip-address/203.0.113.7")

    def test_iso_utc(self):
        self.assertEqual(iso_utc(1790000000), "2026-09-21T14:13:20Z")
        self.assertEqual(iso_utc("2026-09-27T22:06:27+00:00"), "2026-09-27T22:06:27Z")
        self.assertEqual(iso_utc("2026-09-27T22:06:27Z"), "2026-09-27T22:06:27Z")
        self.assertIsNone(iso_utc("soon"))
        self.assertIsNone(iso_utc(True))
        self.assertIsNone(iso_utc(None))

    def test_get_path(self):
        d = {"a": [{"b": 1}]}
        self.assertEqual(get_path(d, "a", 0, "b"), 1)
        self.assertEqual(get_path(d, "a", 5, "b", default=9), 9)
        self.assertEqual(get_path(d, "a", "b"), None)
        self.assertEqual(get_path("x", "a", default=2), 2)
