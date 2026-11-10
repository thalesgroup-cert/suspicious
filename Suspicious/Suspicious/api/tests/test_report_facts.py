from datetime import datetime, timezone

from django.test import SimpleTestCase

from api.utils.report_facts import (
    IndicatorFacts, apply_fallbacks, band_icon, cap, connector_lines, detail_groups, get_path, iso_utc,
    key_findings, vt_facts,
)

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

    def test_asn_string_length_boundaries(self):
        for raw, want in (("4200000000", 4200000000), ("4294967295", 4294967295),
                          ("99999999999", None), ("00123", 123)):
            for rep in ({"asn": raw}, {"ip": {"asn": raw}}):
                f = apply_fallbacks(IndicatorFacts(), [_src("StopForumSpam_1_0", rep)], "ip")
                self.assertEqual(f.asn, want)


NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def _src_v(name, verdict, tier, evidence="", failed=False):
    return {"name": name, "tier": tier, "verdict": verdict, "confidence": None, "evidence": evidence,
            "failed": failed, "enrichment": None, "report": None}


class DetailGroupTests(SimpleTestCase):
    def test_groups_follow_type_and_hide_empties(self):
        f = IndicatorFacts(country="NL", asn=64500, registrar="Example Registrar LLC", detections=(0, 0, 91))
        self.assertEqual([g.title for g in detail_groups(f, "ip")], ["Location", "Whois/RDAP", "VirusTotal"])
        self.assertEqual([g.title for g in detail_groups(f, "hash")], ["VirusTotal"])
        self.assertIn(("ASN", "AS64500"), detail_groups(f, "ip")[0].rows)
        self.assertEqual(detail_groups(IndicatorFacts(), "url"), [])

    def test_row_formats(self):
        f = IndicatorFacts(detections=(2, 0, 91), total_votes={"malicious": 3, "harmless": 1},
                           popularity_ranks={"Cisco Umbrella": 812}, categories={"VendorX": "phishing"},
                           names=["a"] * 7, size=1024)
        rows = {k: v for g in detail_groups(f, "hash") for k, v in g.rows}
        self.assertEqual(rows["Detections"], "2/91")
        self.assertEqual(rows["Community votes"], "malicious 3, harmless 1")
        self.assertEqual(rows["Popularity"], "Cisco Umbrella #812")
        self.assertEqual(rows["Other names"], "a, a, a, a, a and 2 more")
        self.assertEqual(rows["Size"], "1024")
        rows = {k: v for g in detail_groups(f, "url") for k, v in g.rows}
        self.assertEqual(rows["VendorX"], "phishing")

    def test_long_lists_are_capped(self):
        f = IndicatorFacts(flagged_vendors=[(f"Eng{i:02}", "trojan") for i in range(90)],
                           sandbox_verdicts=[(f"Box{i:02}", "malicious") for i in range(40)],
                           resolved_ips=[f"203.0.113.{i}" for i in range(30)], detections=(90, 0, 95))
        rows = {k: v for g in detail_groups(f, "domain") for k, v in g.rows}
        self.assertTrue(rows["Flagged by"].endswith("Eng09 (trojan) +80 more"))
        self.assertTrue(rows["Sandbox verdicts"].endswith("+30 more"))
        self.assertTrue(rows["IP addresses"].endswith("203.0.113.4 and 25 more"))
        self.assertLess(len(rows["Flagged by"]), 400)

    def test_cap_and_band_icon(self):
        self.assertEqual(cap(["a", "b"], 5, " and {n} more"), "a, b")
        self.assertEqual((band_icon("Dangerous"), band_icon("On Going"), band_icon(None)), ("🔴", "⚪", "⚪"))


class ConnectorLineTests(SimpleTestCase):
    def test_connector_order_icons_and_labels(self):
        lines = connector_lines([
            _src_v("Urlscan_io_Search", "no-data", tier=3), _src_v("SpamhausDBL_1_0", "clean", tier=2, evidence="not listed"),
            _src_v("Zscaler_1_3", "suspicious", tier=2, evidence="Phishing"), _src_v("VirusTotal_GetReport_3_1", "malicious", tier=1),
            _src_v("Shodan", "no-data", tier=1, failed=True)], IndicatorFacts(detections=(2, 0, 91)))
        self.assertEqual([(l.icon, l.name, l.label) for l in lines], [
            ("🔴", "VirusTotal_GetReport_3_1", "2/91 detections"), ("🟠", "Zscaler_1_3", "Phishing"),
            ("🟢", "SpamhausDBL_1_0", "not listed"), ("⚪", "Shodan", "failed"), ("⚪", "Urlscan_io_Search", "no data")])

    def test_plain_labels_without_evidence(self):
        lines = connector_lines([_src_v("B", "clean", 2), _src_v("A", "clean", 2)], IndicatorFacts())
        self.assertEqual([(l.name, l.label) for l in lines], [("A", "safe"), ("B", "safe")])

    def test_virustotal_by_enrichment_source(self):
        s = _src_v("Other", "malicious", 1)
        s["enrichment"] = {"source": "virustotal"}
        self.assertEqual(connector_lines([s], IndicatorFacts(detections=(1, 0, 5)))[0].label, "1/5 detections")


class KeyFindingTests(SimpleTestCase):
    def test_findings_rules_need_their_fact(self):
        self.assertEqual(key_findings(IndicatorFacts(), [], "203.0.113.7", "ip", NOW), [])

    def test_findings_order_and_cap(self):
        f = IndicatorFacts(detections=(3, 0, 90), threat_names=["Phish.Kit"], brands=["ExampleBank"],
                           created="2026-11-07T00:00:00Z", final_url="https://collect.test/x",
                           popularity_ranks={"Cisco Umbrella": 500})
        out = key_findings(f, [_src_v("MISP_2_1", "malicious", tier=2, evidence="Phishing campaign")],
                           "https://login-example.test/a", "url", NOW)
        self.assertEqual(out, ["Listed by MISP_2_1: Phishing campaign", "3 of 90 VirusTotal engines flag it as malicious",
                               "Threat name: Phish.Kit", "Shows the ExampleBank brand on another domain",
                               "Domain registered 3 days ago"])

    def test_brand_matching_the_domain_is_not_impersonation(self):
        self.assertEqual(key_findings(IndicatorFacts(brands=["Example Bank"]), [], "examplebank.test", "domain", NOW), [])

    def _brand(self, value, dtype="url"):
        return key_findings(IndicatorFacts(brands=["Example Bank"]), [], value, dtype, NOW)

    def test_brand_on_hyphenated_own_domain_is_not_impersonation(self):
        self.assertEqual(self._brand("https://example-bank.test/login"), [])

    def test_brand_on_its_real_domain_with_subdomain_is_not_impersonation(self):
        self.assertEqual(self._brand("https://login.examplebank.test/x"), [])

    def test_brand_as_subdomain_lure_is_impersonation(self):
        self.assertEqual(self._brand("https://examplebank.test.evil.test/x"),
                         ["Shows the Example Bank brand on another domain"])

    def test_brand_on_plain_other_domain_is_impersonation(self):
        self.assertEqual(self._brand("https://other.test/x"), ["Shows the Example Bank brand on another domain"])

    def test_brand_with_empty_host_gives_no_finding(self):
        self.assertEqual(self._brand("", "domain"), [])

    def test_redirect_between_www_and_bare_domain_is_not_a_redirect(self):
        f = IndicatorFacts(final_url="https://examplebank.test/")
        self.assertEqual(key_findings(f, [], "https://www.examplebank.test/", "url", NOW), [])
        f = IndicatorFacts(final_url="https://other.test/")
        self.assertEqual(key_findings(f, [], "https://www.examplebank.test/", "url", NOW), ["Redirects to other.test"])

    def test_remaining_rules(self):
        f = IndicatorFacts(created="2026-11-10T00:00:00Z", final_url="https://collect.test/x",
                           popularity_ranks={"Cisco Umbrella": 500}, threat_label="trojan.test")
        out = key_findings(f, [_src_v("Spamhaus", "malicious", 2), _src_v("Zscaler_1", "malicious", 2, failed=True)],
                           "login-example.test", "domain", NOW)
        self.assertEqual(out, ["Listed by Spamhaus", "Threat name: trojan.test", "Domain registered today",
                               "Ranked #500 by Cisco Umbrella"])
        out = key_findings(IndicatorFacts(final_url="https://collect.test/x"), [], "https://a.test/", "url", NOW)
        self.assertEqual(out, ["Redirects to collect.test"])
