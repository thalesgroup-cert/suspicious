from django.test import SimpleTestCase

from api.utils.report_facts import IndicatorFacts, apply_fallbacks, get_path, iso_utc, vt_facts

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

    def _facts(self, attrs, dt="domain"):
        return vt_facts(None, {"results": {"data": {"attributes": attrs}}}, dt, "x")

    def test_out_of_range_timestamps_do_not_raise(self):
        for ts in (10**15, -10**15, 10**30, float("inf")):
            self.assertIsNone(iso_utc(ts))
            self.assertIsNone(self._facts({"creation_date": ts}).created)
        self.assertIsNone(iso_utc("0001-01-01T00:00:00+23:59"))

    def test_unhashable_or_wrong_typed_nested_values(self):
        f = self._facts({
            "last_analysis_results": {"E1": {"category": ["malicious"], "result": "x"},
                                      "E2": {"category": {"a": 1}, "result": "y"}},
            "rdap": {"events": [{"event_action": ["expiration"], "event_date": "2027-01-01T00:00:00Z"},
                                {"event_action": {"a": 1}, "event_date": "2027-01-01T00:00:00Z"}],
                     "entities": [{"roles": 5, "vcard_array": [{"name": "fn", "values": ["A"]}]},
                                  {"roles": "registrant", "vcard_array": "x"},
                                  {"roles": ["registrant"], "vcard_array": [{"name": "fn", "values": ["Real"]}]}]}})
        self.assertEqual(f.flagged_vendors, [])
        self.assertIsNone(f.expires)
        self.assertEqual(f.registrant, "Real")

    def test_source_precedence_attributes_then_rdap_then_whois(self):
        rdap = {"events": [{"event_action": "registration", "event_date": "2026-02-02T00:00:00Z"},
                           {"event_action": "expiration", "event_date": "2027-02-02T00:00:00Z"}]}
        whois = ("Registrar: Whois Reg\nCreation Date: 2026-03-03T00:00:00Z\n"
                 "Registry Expiry Date: 2027-03-03T00:00:00Z\n")
        f = self._facts({"registrar": "Attr Reg", "creation_date": 1790000000, "rdap": rdap, "whois": whois})
        self.assertEqual((f.registrar, f.created, f.expires), ("Attr Reg", "2026-09-21T14:13:20Z", "2027-02-02T00:00:00Z"))
        f = self._facts({"rdap": rdap, "whois": whois})
        self.assertEqual((f.registrar, f.created), ("Whois Reg", "2026-02-02T00:00:00Z"))
        f = self._facts({"whois": whois})
        self.assertEqual((f.created, f.expires), ("2026-03-03T00:00:00Z", "2027-03-03T00:00:00Z"))


def _src(name, report, failed=False):
    return {"name": name, "tier": 2, "verdict": "no-data", "confidence": None, "evidence": "",
            "failed": failed, "enrichment": None, "report": report}


class FallbackTests(SimpleTestCase):
    def test_dshield_fills_ip_location_when_vt_is_empty(self):
        f = apply_fallbacks(IndicatorFacts(), [_src("DShield_lookup_1_0", {
            "asname": "EXAMPLE-AS", "ascountry": "NL", "network": "203.0.113.0/24",
            "asabusecontact": "abuse@as.test", "attacks": 12})], "ip")
        self.assertEqual((f.as_owner, f.country, f.network), ("EXAMPLE-AS", "NL", "203.0.113.0/24"))

    def test_stopforumspam_fills_asn_and_country(self):
        f = apply_fallbacks(IndicatorFacts(), [_src("StopForumSpam_1_0", {"ip": {"asn": 64500, "country": "fr", "appears": 1}})], "ip")
        self.assertEqual((f.asn, f.country), (64500, "fr"))

    def test_stopforumspam_top_level_and_digit_string_asn(self):
        f = apply_fallbacks(IndicatorFacts(), [_src("StopForumSpam_1_0", {"asn": "64501", "country": 7})], "ip")
        self.assertEqual((f.asn, f.country), (64501, None))

    def test_vt_value_is_never_overwritten(self):
        f = apply_fallbacks(IndicatorFacts(country="DE"), [_src("DShield_lookup_1_0", {"ascountry": "NL"})], "ip")
        self.assertEqual(f.country, "DE")

    def test_zscaler_categorization_for_url(self):
        f = apply_fallbacks(IndicatorFacts(), [_src("Zscaler_1_3", {
            "urlClassifications": ["PHISHING", "MISCELLANEOUS"], "urlClassificationsWithSecurityAlert": ["PHISHING"]})], "url")
        self.assertEqual(f.categories, {"Zscaler": "PHISHING, MISCELLANEOUS"})

    def test_failed_or_placeholder_sources_fill_nothing(self):
        f = apply_fallbacks(IndicatorFacts(), [_src("DShield_lookup_1_0", {"ongoing": True}),
                                               _src("StopForumSpam_1_0", {"asn": 1}, failed=True)], "ip")
        self.assertEqual(f, IndicatorFacts())

    def test_location_fallbacks_do_not_apply_to_domains(self):
        f = apply_fallbacks(IndicatorFacts(), [_src("DShield_lookup_1_0", {"ascountry": "NL"})], "domain")
        self.assertIsNone(f.country)

    def test_wrong_typed_payloads_do_not_raise(self):
        for rep in (None, "x", [1], {"ip": 3, "urlClassifications": "PHISHING"}, {"asname": 5}):
            apply_fallbacks(IndicatorFacts(), [_src("DShield_lookup_1_0", rep), _src("StopForumSpam_1_0", rep),
                                               _src("Zscaler_1_3", rep)], "ip")

    def test_hostile_asn_strings_do_not_raise(self):
        for bad in ("²", "9" * 5000):
            for rep in ({"asn": bad}, {"ip": {"asn": bad}}):
                f = apply_fallbacks(IndicatorFacts(), [_src("StopForumSpam_1_0", rep)], "ip")
                self.assertIsNone(f.asn)
