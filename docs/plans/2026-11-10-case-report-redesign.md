# Case report redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the downloadable case report's single generic layout with one short, type-specific block per indicator (plus mail and file evidence and the mail AI assessment), built from data Suspicious already stores and rendered identically as HTML and Markdown.

**Architecture:** Pure extractors in `api/utils/report_facts.py` turn each indicator's newest analyzer reports (`enrichment`, `report_full`, the source verdict) into typed facts, detail groups, connector lines and key findings. `api/utils/case_report_model.py` collects a case (group, mail or file) into one `CaseReport` dataclass tree with a bounded, indicator-count-independent number of queries. The Markdown builder and the Django template only render that model; the two views build it once and keep their permissions, URLs, content types and the 6 MiB screenshot cap.

**Tech Stack:** Python 3 / Django 5 (DRF views, Django templates with autoescape), `dataclasses`, Django `TestCase`/`SimpleTestCase`; tests run with `ww test backend <label>` from the repo root.

**Spec:** `docs/specs/2026-11-10-case-report-redesign-design.md` (binding). Data inventory: `/home/forensics/.claude/jobs/376a0ae5/tmp/report-data-inventory.md`.

Paths below are relative to `Suspicious/Suspicious/` unless they start with `docs/` or `CHANGELOG.md`.

## Global Constraints

Copied from the spec; every task obeys them.

- **Icons.** Indicator and case bands: 🔴 Dangerous, 🟠 Suspicious, 🟢 Safe, ⚪ Inconclusive (any other case result, e.g. `On Going`, `Failure`, `AllowListed`, also ⚪). Connector lines: malicious 🔴, suspicious 🟠, clean 🟢 (worded "safe"), no-data or failed ⚪.
- **Legend wording** (one constant, `LEGEND`, used by both renderers): `🔴 malicious / dangerous  🟠 suspicious  🟢 safe  ⚪ failed / unknown / inconclusive`. Rendered once, at the top of the indicators section (and of the case-level connector list when there is one), headed **Legend**.
- **Connector order:** 🔴, 🟠, 🟢, ⚪, then tier ascending, then name (case-insensitive). One line per analyzer that ran for the indicator, the newest report per analyzer. Label: VirusTotal `m/total detections`; a failed source `failed`; otherwise the source's evidence text, else `malicious` / `suspicious` / `safe` / `no data`.
- **Indicator order:** Dangerous, Suspicious, Safe, Inconclusive (no verdict sorts last), then value.
- **Caps:** reverse-DNS and resolved names at most **5** plus `and N more`; malicious/suspicious vendors at most **10** plus `+N more` (same cap for sandbox verdicts); name servers all; at most **10 full indicator blocks** per report, the rest listed in the indicator table with a `+N more` line; key findings at most **5**; screenshots only in HTML, inside a collapsed `<details>`, under the existing **6 MiB** total cap (`_REPORT_IMG_CAP = 6 * 1024 * 1024`).
- **Which indicators get a block.** Group (IOC) cases: every indicator, in indicator order, up to 10; an indicator table appears only when there are more than 10. Mail cases: an indicator table of all embedded indicators (value, type, verdict, top finding) always, and a full block only for Dangerous and Suspicious indicators that are not mail addresses, up to 10. File cases: one "Case analysis" block (Hash group plus connector list), no indicator table. *(Interpretation of the spec's two statements; the owner can overrule.)*
- **Date format:** UTC ISO 8601 `%Y-%m-%dT%H:%M:%SZ` (e.g. `2026-09-27T22:06:27Z`) for every date shown (case created, report generated, VT and RDAP dates, `analysed_at`). Ages ("registered 3 days ago") only inside Key findings.
- **Confidence:** a percentage, `f"{round(float(x))}%"`; omitted when None. Case header uses `case.final_confidence`, blocks use the observable verdict's `confidence`.
- **Escaping.** Markdown: every external value goes through `_text` or `_code` from `api/utils/case_report_markdown.py` (indicator values through `_code`, everything else through `_text`), including detail rows, findings, connector labels, AI fields. HTML: Django autoescape only; no `|safe`, no `mark_safe`, no `|pprint`. The only non-escaped value stays the server-built `data:image/png;base64,` URI. A link (`href`) is emitted only for the VirusTotal link, and only when it starts with `https://www.virustotal.com/gui/`; final URLs, redirects and other URLs are plain text.
- **No raw analyzer output** in either format (no `report_full`, no `pprint`, no whois blob).
- **Hide empties:** a field without a value, a group without rows, and a group not applicable to the type are not rendered.
- **Detail groups per type:** IP: Location, Whois/RDAP, Categorization, VirusTotal. Domain: Location (resolved IPs), Whois/RDAP, Categorization, VirusTotal. URL: URL, Location, Categorization, VirusTotal. Hash/file: Hash, VirusTotal. Mail address: no block. VirusTotal fills first; fallbacks only when VirusTotal has no value: DShield or StopForumSpam for IP Location (country, ASN, AS name, network), Zscaler for Categorization.
- **AI model assessment:** only on mail cases, only while the `ai_model` connector is enabled and the case has an assessment with a `model_version`, built for the downloading user via `api.utils.ai_assessment.ai_assessment_for(case, request)` (which calls `ai_model.presentation.present_assessment`). Cross-check facts and campaign folder labels only when the payload carries them (analysts). Historical Cortex AI reports (`analyzer.name == ai_analyzer_name()`) never appear. The AI vote also appears as a case-level connector line `AI model: <Result>, <Tier> confidence`.
- **Unchanged:** permissions (`IsAuthenticated, CanAccessSubmission` + `submission_queryset`), URLs (`cases/<id>/report/`, `cases/<id>/report.md`), content types and `Content-Disposition` filenames, scoring and verdicts. No new analyzers, connectors, models or migrations. The investigation API output of `assemble_observables` is unchanged (additions are new functions only).
- **Fixtures** use the real payload key shapes listed in the spec with made-up values (documentation IPs `203.0.113.0/24`, `198.51.100.0/24`, `.test` domains); never real data.
- **Commits:** Conventional Commits; `git add <explicit paths>`, never `-A`.

## Review Focus

Spec-implied failure modes no task's happy-path tests cover; each has a dedicated test in the task that owns the code.

1. **A payload key present but null or the wrong type** (`last_analysis_stats: null`, `rdap: "text"`, `popularity_ranks: []`, `asn: "AS64500"`, `last_dns_records: {"A": "x"}`, `creation_date: "soon"`): extractors skip the field, never raise. Task 1 `test_wrong_types_and_nulls_are_ignored`.
2. **An indicator whose every source failed** (all reports `status="Failure"`): block renders with verdict Inconclusive, every connector line `⚪ <name>: failed`, no Details, no Key findings. Task 4 `test_indicator_with_every_source_failed`.
3. **An IOC value or analyzer text containing Markdown or HTML specials** (`` http://evil.test/`a`|b<script>alert(1)</script>[x](javascript:1) ``, a registrar named `# Evil_ *Corp*`): no live link, no heading, no table break, no unescaped tag. Task 6 `test_indicator_value_and_details_are_escaped`, Task 7 `test_html_escapes_values_and_links_only_virustotal`.
4. **A mail case whose AI assessment is absent, whose connector is off, or whose viewer is the reporter**: no section when absent or off; a reporter's section has no cross-check and no campaign labels. Task 5 `test_reporter_sees_no_cross_check` and `test_no_section_without_assessment_or_when_disabled`.
5. **A very large vendor list** (90 malicious engines, 40 sandbox verdicts, 30 resolved IPs): rows capped at 10 / 10 / 5 with the exact overflow text. Task 3 `test_long_lists_are_capped`.

---

### Task 1: Fact model and VirusTotal extractors

**Files:**
- Create: `api/utils/report_facts.py`
- Test: `api/tests/test_report_facts.py`

**Interfaces:**
- Consumes: `score_process.scoring.enrichment.virustotal._attributes(report_full) -> dict | None`, `_iso(ts) -> str | None`, `_vt_link(data_type, value) -> str | None` (import them; do not copy). `AnalyzerReport.enrichment` dict shape (keys `malicious_count`, `suspicious_count`, `total`, `vendors[{name, category, result}]`, `reputation`, `tags`, `first_seen`, `last_seen`, `as_owner`, `asn`, `country`, `continent`, `network`, `registrar`, `creation_date`, `categories`, `final_url`, `page_title`, `meaningful_name`, `size`, `type_description`, `names`, `threat_label`).
- Produces:
  - `def get_path(obj: Any, *keys: str | int, default=None) -> Any` — walks dicts/lists; returns `default` on any missing key, wrong container type or index error.
  - `def iso_utc(value: Any) -> str | None` — int/float unix seconds, `datetime`, or ISO string (with `Z` or offset) to `%Y-%m-%dT%H:%M:%SZ`; anything else None.
  - `@dataclass class IndicatorFacts` with every field defaulting to None / empty: `detections: tuple[int, int, int] | None` (malicious, suspicious, total); `flagged_vendors: list[tuple[str, str | None]]` (name, result; malicious first, then suspicious); `reputation: int | None`; `tags: list[str]`; `total_votes: dict[str, int]`; `threat_severity: str | None`; `country`, `continent`, `as_owner`, `network`, `rir: str | None`; `asn: int | None`; `resolved_ips: list[str]`; `registrar`, `created`, `updated`, `expires`, `registrant: str | None`; `contact_emails`, `contact_phones`, `name_servers`, `statuses: list[str]`; `categories: dict[str, str]`; `popularity_ranks: dict[str, int]`; `final_url`, `title: str | None`; `http_code: int | None`; `brands: list[str]`; `threat_names: list[str]`; `first_submission`, `last_submission`, `last_analysis: str | None`; `times_submitted`, `outgoing_links: int | None`; `meaningful_name`, `type_description`, `md5`, `sha1`, `sha256`, `threat_label: str | None`; `names: list[str]`; `size: int | None`; `sandbox_verdicts: list[tuple[str, str]]` (vendor, category/malware name); `vt_link: str | None`.
  - `def vt_facts(enrichment: dict | None, report_full: Any, data_type: str, value: str) -> IndicatorFacts` — enrichment values first, `report_full` attributes fill the rest; `vt_link` from `_vt_link(data_type, value)`.

**VT key shapes used in fixtures** (attributes under `report_full["results"]["data"]["attributes"]`, also accepted under `results.attributes`): `last_analysis_stats {malicious, suspicious, undetected, harmless, timeout}`, `last_analysis_results {engine: {category, result}}`, `reputation`, `tags`, `total_votes {harmless, malicious}`, `threat_severity {threat_severity_level}`; domain `registrar`, `creation_date` (unix), `last_update_date` (unix), `rdap {entities[{roles[], vcard_array[{name, values[]}]}], nameservers[{ldh_name}], status[], events[{event_action, event_date}]}`, `whois` (text), `categories {vendor: category}`, `popularity_ranks {source: {rank, timestamp}}`, `last_dns_records [{type, value}]`; IP `country`, `continent`, `asn`, `as_owner`, `network`, `regional_internet_registry`, `rdap`; URL `last_final_url`, `title`, `last_http_response_code`, `categories`, `threat_names`, `identified_brands` (strings or `{name}` dicts), `main_brand`, `first_submission_date`, `times_submitted`, `outgoing_links []`; hash `first_submission_date`, `last_submission_date`, `last_analysis_date`, `meaningful_name`, `names`, `type_description`, `size`, `md5`, `sha1`, `sha256`, `sandbox_verdicts {sandbox: {category, malware_names[]}}`, `popular_threat_classification {suggested_threat_label}`.

- [ ] **Step 1: Write the failing tests** (`SimpleTestCase`, no DB):

```python
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

class VtFactsTests(SimpleTestCase):
    def test_domain_facts_from_report_full(self):
        f = vt_facts(None, VT_DOMAIN, "domain", "login-example.test")
        self.assertEqual(f.detections, (2, 1, 91))
        self.assertEqual(f.flagged_vendors, [("EngineA", "phishing"), ("EngineB", None)])
        self.assertEqual(f.registrar, "Example Registrar LLC")
        self.assertEqual(f.created, "2026-09-21T14:13:20Z")
        self.assertEqual(f.registrant, "Jane Doe")
        self.assertEqual(f.contact_emails, ["abuse@registrar.test"])
        self.assertEqual(f.name_servers, ["ns1.example.test", "ns2.example.test"])
        self.assertEqual(f.expires, "2027-09-27T22:06:27Z")
        self.assertEqual(f.resolved_ips, ["203.0.113.10", "2001:db8::1"])
        self.assertEqual(f.popularity_ranks, {"Cisco Umbrella": 812})
        self.assertEqual(f.vt_link, "https://www.virustotal.com/gui/domain/login-example.test")

    def test_enrichment_wins_over_report_full(self):
        f = vt_facts({"malicious_count": 42, "total": 70, "suspicious_count": 0, "as_owner": "Evil Hosting LLC"},
                     {"results": {"data": {"attributes": {"as_owner": "Other", "country": "NL"}}}}, "ip", "203.0.113.7")
        self.assertEqual(f.detections, (42, 0, 70))
        self.assertEqual(f.as_owner, "Evil Hosting LLC")
        self.assertEqual(f.country, "NL")

    def test_ip_url_and_hash_fields(self): ...  # one fixture per type; asserts asn == 64500, network,
        # rir; final_url, title, http_code == 200, brands == ["ExampleBank"], outgoing_links == 3,
        # threat_names; md5/sha256, size == 1024, sandbox_verdicts == [("Zenbox", "malicious")],
        # threat_label == "trojan.test", last_submission/last_analysis ISO strings

    def test_wrong_types_and_nulls_are_ignored(self):
        bad = {"results": {"data": {"attributes": {
            "last_analysis_stats": None, "last_analysis_results": [], "rdap": "text",
            "popularity_ranks": [], "asn": "AS64500", "last_dns_records": {"A": "x"},
            "creation_date": "soon", "categories": None, "identified_brands": [None, 3]}}}}
        for dt in ("ip", "domain", "url", "hash"):
            f = vt_facts(None, bad, dt, "x")
            self.assertIsNone(f.detections); self.assertIsNone(f.asn); self.assertIsNone(f.created)
            self.assertEqual((f.resolved_ips, f.popularity_ranks, f.brands), ([], {}, []))

    def test_no_vt_payload_gives_empty_facts_but_link(self):
        f = vt_facts(None, {"ongoing": True}, "ip", "203.0.113.7")
        self.assertIsNone(f.detections)
        self.assertEqual(f.vt_link, "https://www.virustotal.com/gui/ip-address/203.0.113.7")

    def test_iso_utc(self):
        self.assertEqual(iso_utc(1790000000), "2026-09-21T14:13:20Z")
        self.assertEqual(iso_utc("2026-09-27T22:06:27+00:00"), "2026-09-27T22:06:27Z")
        self.assertIsNone(iso_utc("soon"))
```

(`1790000000` is `2026-09-21T14:13:20Z`.)

- [ ] **Step 2: Run, expect FAIL** — `ww test backend api.tests.test_report_facts` (ImportError).
- [ ] **Step 3: Implement** `get_path`, `iso_utc`, `IndicatorFacts`, `vt_facts` in `api/utils/report_facts.py`. Notes the signatures don't settle: `whois` raw text is read only to fill `registrar`/`created`/`updated`/`expires` when attributes and RDAP lack them, by matching lines `Registrar:`, `Creation Date:`, `Updated Date:`, `Registry Expiry Date:`; RDAP registrant is the `fn` of the entity whose `roles` contains `registrant`, emails/phones from every entity's `email`/`tel` vcard entries (deduplicated, order kept); `resolved_ips` from `last_dns_records` entries of type `A`/`AAAA` only; `threat_severity` is `threat_severity.threat_severity_level` when it is a str. No field may raise; wrap nothing in a broad `try`, rely on `get_path` and `isinstance` checks.
- [ ] **Step 4: Run, expect PASS** — `ww test backend api.tests.test_report_facts`.
- [ ] **Step 5: Commit**
```bash
git add Suspicious/Suspicious/api/utils/report_facts.py Suspicious/Suspicious/api/tests/test_report_facts.py
git commit -m "feat(report): extract per-type VirusTotal facts for the case report"
```

### Task 2: Fallback extractors (DShield, StopForumSpam, Zscaler)

**Files:**
- Modify: `api/utils/report_facts.py`
- Test: `api/tests/test_report_facts.py` (new class `FallbackTests`)

**Interfaces:**
- Consumes: `IndicatorFacts` (Task 1); a source dict as produced by `_source_rows` / `assemble_observables`: `{"name": str, "tier": int, "verdict": str, "confidence": int | None, "evidence": str, "failed": bool, "enrichment": dict | None, "report": Any}` where `report` is `report_full`.
- Produces: `def apply_fallbacks(facts: IndicatorFacts, sources: list[dict], data_type: str) -> IndicatorFacts` — returns a copy (`dataclasses.replace`) where only empty fields are filled. Source matched by `name.lower().startswith(prefix)`: `"dshield"` (keys `asname`, `ascountry`, `network`; IP only), `"stopforumspam"` (keys `asn`, `country`, read at top level, else under `report["ip"]`; IP only), `"zscaler"` (`urlClassifications` list into `categories` as `{"Zscaler": ", ".join(...)}`; URL, domain, IP). Failed sources are skipped.

- [ ] **Step 1: Failing tests**
```python
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
```
- [ ] **Step 2: Run, expect FAIL** — `ww test backend api.tests.test_report_facts`.
- [ ] **Step 3: Implement** `apply_fallbacks(facts, sources, data_type)` in `api/utils/report_facts.py`. `asn` accepted only as int (or digit-only str converted); non-str country ignored.
- [ ] **Step 4: Run, expect PASS** — `ww test backend api.tests.test_report_facts`.
- [ ] **Step 5: Commit**
```bash
git add Suspicious/Suspicious/api/utils/report_facts.py Suspicious/Suspicious/api/tests/test_report_facts.py
git commit -m "feat(report): fall back to DShield, StopForumSpam and Zscaler for location and categories"
```

### Task 3: Detail groups, connector lines, key findings and ordering

**Files:**
- Modify: `api/utils/report_facts.py`
- Test: `api/tests/test_report_facts.py` (classes `DetailGroupTests`, `ConnectorLineTests`, `KeyFindingTests`)

**Interfaces:**
- Consumes: `IndicatorFacts`, source dicts (Task 2 shape).
- Produces:
  - `@dataclass(frozen=True) class DetailGroup: title: str; rows: list[tuple[str, str]]` — row values are plain, unescaped strings.
  - `@dataclass(frozen=True) class ConnectorLine: icon: str; name: str; label: str; verdict: str; tier: int`.
  - Constants: `LEGEND: str` (exact wording in Global Constraints); `BAND_ICON = {"Dangerous": "🔴", "Suspicious": "🟠", "Safe": "🟢", "Inconclusive": "⚪"}`; `BAND_RANK = {"Dangerous": 0, "Suspicious": 1, "Safe": 2, "Inconclusive": 3}`; `VERDICT_ICON = {"malicious": "🔴", "suspicious": "🟠", "clean": "🟢", "no-data": "⚪"}`; `GROUPS_BY_TYPE = {"ip": ("Location", "Whois/RDAP", "Categorization", "VirusTotal"), "domain": ("Location", "Whois/RDAP", "Categorization", "VirusTotal"), "url": ("URL", "Location", "Categorization", "VirusTotal"), "hash": ("Hash", "VirusTotal"), "file": ("Hash", "VirusTotal")}`.
  - `def band_icon(band: str | None) -> str` (unknown/None → ⚪).
  - `def cap(items: list[str], limit: int, more: str) -> str` — `", ".join(items[:limit])` plus `more.format(n=len(items) - limit)` when over; `more` is `" and {n} more"` (names) or `" +{n} more"` (vendors).
  - `def detail_groups(facts: IndicatorFacts, data_type: str) -> list[DetailGroup]` — groups in `GROUPS_BY_TYPE` order, empty rows dropped, empty groups dropped. Rows: Location `IP addresses` (resolved, cap 5 " and {n} more"), `Country`, `ASN` (`AS64500`), `AS owner`, `Network`, `RIR`; Whois/RDAP `Registrar`, `Registrant`, `Contact emails`, `Contact phones`, `Name servers` (all), `Status`, `Created`, `Updated`, `Expires`; Categorization one row per vendor; URL `Final URL`, `Redirects to another host` handled in findings only, `Title`, `HTTP code`, `Brands`, `First submitted`, `Times submitted`, `Outgoing links`; Hash `File name`, `Other names` (cap 5), `File type`, `Size` (bytes), `MD5`, `SHA-1`, `SHA-256`, `Threat label`, `First submitted`, `Last submitted`, `Last analysed`; VirusTotal `Detections` (`m/total`), `Flagged by` (`Name (result)` items, cap 10 " +{n} more"), `Sandbox verdicts` (cap 10), `Reputation`, `Community votes` (`malicious 3, harmless 1`), `Threat severity`, `Tags`, `Popularity` (`Cisco Umbrella #812`).
  - `def connector_lines(sources: list[dict], facts: IndicatorFacts) -> list[ConnectorLine]` — failed → `⚪`, label `failed`; VirusTotal (name starts with `virustotal` case-insensitive, or `enrichment.source == "virustotal"`) with `facts.detections` → label `f"{m}/{total} detections"`; sorted per Global Constraints.
  - `def key_findings(facts: IndicatorFacts, sources: list[dict], value: str, data_type: str, now: datetime) -> list[str]` — fixed rule order, each rule fires only with its input fact, result capped at 5: (1) blocklist or MISP hit: a non-failed source whose name starts with `spamhaus`, `misp`, `googlesafebrowsing`, `phishtank` or `zscaler` and whose verdict is malicious or suspicious → `"Listed by {name}: {evidence}"` (`: evidence` only when non-empty); (2) detections: `facts.detections[0] > 0` → `"{m} of {total} VirusTotal engines flag it as malicious"`; (3) threat name: `threat_label` or first `threat_names` → `"Threat name: {x}"`; (4) brand impersonation: a brand whose lowercase alphanumerics are not in the indicator host → `"Shows the {brand} brand on another domain"`; (5) young domain: domain or URL with `created` less than 30 days before `now` → `"Domain registered {d} days ago"` (`today` for 0); (6) redirect: URL whose `final_url` host differs from the value's host → `"Redirects to {host}"`; (7) top popularity: any rank ≤ 1000 → `"Ranked #{rank} by {source}"`.

- [ ] **Step 1: Failing tests** (all `SimpleTestCase`):
```python
NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)

def test_groups_follow_type_and_hide_empties(self):
    f = IndicatorFacts(country="NL", asn=64500, registrar="Example Registrar LLC", detections=(0, 0, 91))
    self.assertEqual([g.title for g in detail_groups(f, "ip")], ["Location", "VirusTotal"])
    self.assertEqual([g.title for g in detail_groups(f, "hash")], ["VirusTotal"])
    self.assertIn(("ASN", "AS64500"), detail_groups(f, "ip")[0].rows)
    self.assertEqual(detail_groups(IndicatorFacts(), "url"), [])

def test_long_lists_are_capped(self):
    f = IndicatorFacts(flagged_vendors=[(f"Eng{i:02}", "trojan") for i in range(90)],
                       sandbox_verdicts=[(f"Box{i:02}", "malicious") for i in range(40)],
                       resolved_ips=[f"203.0.113.{i}" for i in range(30)], detections=(90, 0, 95))
    rows = {k: v for g in detail_groups(f, "domain") for k, v in g.rows}
    self.assertTrue(rows["Flagged by"].endswith("Eng09 (trojan) +80 more"))
    self.assertTrue(rows["Sandbox verdicts"].endswith("+30 more"))
    self.assertTrue(rows["IP addresses"].endswith("203.0.113.4 and 25 more"))
    self.assertLess(len(rows["Flagged by"]), 400)

def test_connector_order_icons_and_labels(self):
    lines = connector_lines([
        _src_v("Urlscan_io_Search", "no-data", tier=3), _src_v("SpamhausDBL_1_0", "clean", tier=2, evidence="not listed"),
        _src_v("Zscaler_1_3", "suspicious", tier=2, evidence="Phishing"), _src_v("VirusTotal_GetReport_3_1", "malicious", tier=1),
        _src_v("Shodan", "no-data", tier=1, failed=True)], IndicatorFacts(detections=(2, 0, 91)))
    self.assertEqual([(l.icon, l.name, l.label) for l in lines], [
        ("🔴", "VirusTotal_GetReport_3_1", "2/91 detections"), ("🟠", "Zscaler_1_3", "Phishing"),
        ("🟢", "SpamhausDBL_1_0", "not listed"), ("⚪", "Shodan", "failed"), ("⚪", "Urlscan_io_Search", "no data")])

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
```
(`_src_v(name, verdict, tier, evidence="", failed=False)` is a test helper building the Task 2 source dict.)
- [ ] **Step 2: Run, expect FAIL** — `ww test backend api.tests.test_report_facts`.
- [ ] **Step 3: Implement** the dataclasses, constants and functions above in `api/utils/report_facts.py`. Host comparison uses `urllib.parse.urlsplit(...).hostname`; a value without scheme is its own host.
- [ ] **Step 4: Run, expect PASS** — `ww test backend api.tests.test_report_facts`.
- [ ] **Step 5: Commit**
```bash
git add Suspicious/Suspicious/api/utils/report_facts.py Suspicious/Suspicious/api/tests/test_report_facts.py
git commit -m "feat(report): detail groups, ordered connector lines and key findings per indicator"
```

### Task 4: Case report model and collectors (group, mail, file)

**Files:**
- Create: `api/utils/case_report_model.py`
- Modify: `api/utils/observable_report.py` (extract a shared helper, add two functions; `assemble_observables` output unchanged), `score_process/scoring/observable_collect.py` (add `file_reports`)
- Test: `api/tests/test_case_report_model.py`; existing `api/tests/test_observable_report_derived.py` and `score_process/tests/test_observable_collect_mail.py` must stay green.

**Interfaces:**
- Consumes: `observable_reports(case)`, `mail_observable_reports(mail)`, `_bucket_reports(triples)` (`score_process/scoring/observable_collect.py`); `source_verdict_from_report(report) -> SourceVerdict`; `score_observable(list[SourceVerdict]) -> ObservableVerdict` (`band`, `confidence`, `rationale`); `reports_for_case(case, *, defer_full=False)` (`api/utils/analyzer_reports.py`); `_dedup_analyzer_reports(reports) -> list` (`api/views/investigations.py`); `derive_threat_classification(case, reports) -> dict | None` (`{"label", "category", "source"}`); `analysis_health(reports) -> dict` (`total`, `failed`, `pending`, `failures[{analyzer}]`); `ai_analyzer_name() -> str` (`cortex_job/cortex_utils/cortex_and_job_management.py`); Tasks 1-3.
- Produces:
  - In `observable_collect.py`: `def file_reports(file) -> list[AnalyzerReport]` — reports on the `File` and on `file.linked_hash`, one `_bucket_reports` query, newest first.
  - In `observable_report.py`: `def _source_rows(reports, *, full: bool) -> tuple[list[dict], list[SourceVerdict]]` (the newest-per-analyzer loop now inside `assemble_observables`, which calls it); `def assemble_mail_observables(case, mail, *, full: bool = False) -> list[dict]` (one dict per `mail_observable_reports` row, same keys as `assemble_observables`, `type` = bucket field: `url|ip|hash|domain|mail`, `derived_from=None`, `escalation_note=""`, `screenshot_url` as in `assemble_observables`); `def assemble_file_observable(case, file, *, full: bool = False) -> dict` (`type="file"`, `value=file.linked_hash.value`).
  - In `case_report_model.py`:
    ```python
    @dataclass
    class IndicatorBlock:
        type: str                     # ip|domain|url|hash|file|mail
        value: str
        band: str | None
        confidence: int | None
        why: list[str]                # ObservableVerdict.rationale
        findings: list[str]           # <= 5
        details: list[DetailGroup]
        connectors: list[ConnectorLine]
        vt_link: str | None           # only https://www.virustotal.com/gui/... else None
        derived_from: dict | None     # {"value", "via_analyzer"}
        escalation_note: str = ""
        screenshot_url: str | None = None
        screenshot_data_uri: str | None = None   # set by the HTML view only
        screenshot_omitted: bool = False

    @dataclass(frozen=True)
    class IndicatorRow:
        type: str; value: str; band: str | None; top_finding: str | None

    @dataclass
    class CaseReport:
        case_id: int
        kind: str                     # "group" | "mail" | "file" | "none"
        band: str                     # str(case.results)
        confidence: str | None        # "82%"
        threat: dict | None
        health: str | None            # plain text, e.g. "1 of 3 analyzers failed (Shodan): the verdict has lower confidence"
        lead: str | None              # reporter_paragraph, else inconclusive_reason
        reporter: str
        created: str | None           # ISO UTC
        generated: str                # ISO UTC
        description: str
        reporter_context: str
        why: list[str]                # analyst_paragraph + confidence_reading, else verdict_rationale, else [inconclusive_reason]
        ai: dict | None = None        # Task 5
        case_connectors: list[ConnectorLine] = field(default_factory=list)
        case_analysis: IndicatorBlock | None = None
        rows: list[IndicatorRow] = field(default_factory=list)
        blocks: list[IndicatorBlock] = field(default_factory=list)
        more: int = 0                 # block-eligible indicators beyond the 10-block cap

    BLOCK_CAP = 10
    def build_block(row: dict, *, now: datetime) -> IndicatorBlock
    def build_case_report(case, request, *, now: datetime | None = None) -> CaseReport
    ```
  - `build_case_report` queries: `reports_for_case(case, defer_full=True)` deduped once (threat, health, mail case-level connectors), plus one indicator collector: group → `assemble_observables(case, full=True)`; mail (`case.fileOrMail.mail`) → `assemble_mail_observables(case, mail, full=True)`; file (`case.fileOrMail.file`) → `assemble_file_observable(case, file, full=True)` into `case_analysis` (its band/confidence are the case's, `why=[]`). Mail `case_connectors`: deduped reports with `mail_header_id`, `mail_body_id` or `file_id`, excluding `analyzer.name == ai_analyzer_name()`, through `connector_lines`. `health` uses the same wording as today's `_health_line` without the `**Analysis:**` prefix.

- [ ] **Step 1: Failing tests** (`TestCase`; fixtures as in `test_case_report.py` and `test_observable_collect_mail.py`):
```python
def test_group_blocks_are_ordered_and_typed(self):
    # IP 203.0.113.7 with VirusTotal_GetReport_3_1 (tier 1) level "malicious", report_full=VT_IP fixture;
    # domain safe.test with tier-1 "safe" report.
    rep = build_case_report(self.case, self.request, now=NOW)
    self.assertEqual(rep.kind, "group")
    self.assertEqual([(b.type, b.value, b.band) for b in rep.blocks],
                     [("ip", "203.0.113.7", "Dangerous"), ("domain", "safe.test", "Safe")])
    self.assertEqual(rep.blocks[0].connectors[0].label, "42/70 detections")
    self.assertEqual([g.title for g in rep.blocks[0].details], ["Location", "VirusTotal"])
    self.assertEqual(rep.rows, [])

def test_indicator_with_every_source_failed(self):
    # two reports, status="Failure"
    b = build_case_report(self.case, self.request, now=NOW).blocks[0]
    self.assertEqual(b.band, "Inconclusive")
    self.assertEqual({(l.icon, l.label) for l in b.connectors}, {("⚪", "failed")})
    self.assertEqual((b.details, b.findings), ([], []))

def test_more_than_ten_group_indicators_get_a_table(self):
    # 12 IPs
    rep = build_case_report(self.case, self.request, now=NOW)
    self.assertEqual((len(rep.blocks), len(rep.rows), rep.more), (10, 12, 2))

def test_mail_case_blocks_only_flagged_non_address_indicators(self):
    # mail with embedded URL (malicious), IP (safe), MailAddress (malicious); case.fileOrMail -> mail;
    # a Mail_Header_Analyzer report on mail.mail_header and an AI_Mail_Analyzer report on a file
    rep = build_case_report(self.case, self.request, now=NOW)
    self.assertEqual(rep.kind, "mail")
    self.assertEqual([b.value for b in rep.blocks], ["https://evil.test/x"])
    self.assertEqual({r.type for r in rep.rows}, {"url", "ip", "mail"})
    self.assertIn("Mail_Header_Analyzer", [l.name for l in rep.case_connectors])
    self.assertNotIn("AI_Mail_Analyzer", [l.name for l in rep.case_connectors])

def test_file_case_has_a_case_analysis_block(self):
    rep = build_case_report(self.case, self.request, now=NOW)
    self.assertEqual((rep.kind, rep.case_analysis.type, rep.case_analysis.value), ("file", "file", self.hash.value))
    self.assertEqual([g.title for g in rep.case_analysis.details], ["Hash", "VirusTotal"])
    self.assertEqual(rep.blocks, [])

def test_query_count_does_not_grow_with_indicators(self):
    # same case shape with 1 then 6 indicators, each with 2 reports
    self.assertEqual(self._queries(n=1), self._queries(n=6))

def test_header_fields(self):
    rep = build_case_report(self.case, self.request, now=NOW)
    self.assertEqual(rep.generated, "2026-11-10T00:00:00Z")
    self.assertEqual(rep.confidence, "82%")
    self.assertEqual(rep.why, ["The address is a known C2 host.", "High confidence: 2 of 3 sources agree."])

def test_vt_link_outside_virustotal_is_dropped(self): ...  # build_block with a row whose source enrichment
    # vt_link is "javascript:alert(1)" → block.vt_link is the server-built https link, never the stored one
```
`self.request` is `APIRequestFactory().get("/")` with `request.user = self.user` (DRF `Request` not needed: `ai_assessment_for` reads `request.user` and `request.__dict__`).
- [ ] **Step 2: Run, expect FAIL** — `ww test backend api.tests.test_case_report_model`.
- [ ] **Step 3: Implement** the helpers and `build_block` / `build_case_report`. `build_block`: `facts = apply_fallbacks(vt_facts(vt_src.enrichment, vt_src.report, type, value), sources, type)` where `vt_src` is the VirusTotal source (none → `vt_facts(None, None, ...)`), then `detail_groups`, `connector_lines`, `key_findings`. `vt_link` always comes from `facts.vt_link` (server-built), never from stored enrichment. `mail` type rows get no details (address blocks are never rendered). Sort with `BAND_RANK` then value.
- [ ] **Step 4: Run, expect PASS** — `ww test backend api.tests.test_case_report_model api.tests.test_observable_report_derived score_process.tests.test_observable_collect_mail`.
- [ ] **Step 5: Commit**
```bash
git add Suspicious/Suspicious/api/utils/case_report_model.py Suspicious/Suspicious/api/utils/observable_report.py \
  Suspicious/Suspicious/score_process/scoring/observable_collect.py Suspicious/Suspicious/api/tests/test_case_report_model.py
git commit -m "feat(report): build one case report model for group, mail and file cases"
```

### Task 5: AI model assessment section (mail cases)

**Files:**
- Modify: `api/utils/case_report_model.py`
- Test: `api/tests/test_case_report_model.py` (class `AiSectionTests`)

**Interfaces:**
- Consumes: `api.utils.ai_assessment.ai_assessment_for(case, request) -> dict | None` (None when the connector is off; wraps `present_assessment(case, user, elevated=...)`); payload keys `result` (title case: `Safe|Unwanted|Dangerous|Inconclusive`), `sub_class`, `tier` (`high|medium|low|""`), `runner_up {"result"} | None`, `model_version`, `analysed_at` (datetime), `reads`, `similar_cases`, `campaign {"ref", "size", "labels"?, "members_disagree"?} | None`, `cross_check {"facts": [{"kind", "text"}], "disagrees": bool} | None`.
- Produces: `CaseReport.ai` set only when `kind == "mail"`: the payload with `analysed_at` converted by `iso_utc`; `def ai_connector_line(payload: dict) -> ConnectorLine` — name `AI model`, icon by result (Dangerous 🔴, Unwanted 🟠, Safe 🟢, else ⚪), label `f"{result}, {tier.title()} confidence"` (just `result` when tier empty), tier 0 so it sorts first within its icon; appended to `case_connectors` before sorting.

- [ ] **Step 1: Failing tests** (`ConnectorState.objects.update_or_create(name="ai_model", defaults={"enabled": True})`; `AiAssessment.objects.create(case=case, model_version="v3", result="UNWANTED", sub_class="spam", score=6, confidence=80, tier="high", probabilities={"UNWANTED": 0.8, "SAFE": 0.2})`):
```python
def test_analyst_gets_section_and_cross_check(self):
    rep = build_case_report(self.mail_case, self._request(self.analyst), now=NOW)
    self.assertEqual((rep.ai["result"], rep.ai["sub_class"], rep.ai["tier"]), ("Unwanted", "spam", "high"))
    self.assertIsNotNone(rep.ai["cross_check"])
    self.assertRegex(rep.ai["analysed_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
    self.assertIn(("🟠", "AI model", "Unwanted, High confidence"),
                  [(l.icon, l.name, l.label) for l in rep.case_connectors])

def test_reporter_sees_no_cross_check(self):
    rep = build_case_report(self.mail_case, self._request(self.mail_case.reporter), now=NOW)
    self.assertIsNone(rep.ai["cross_check"])
    self.assertNotIn("labels", rep.ai["campaign"] or {})

def test_no_section_without_assessment_or_when_disabled(self):
    AiAssessment.objects.all().delete()
    self.assertIsNone(build_case_report(self.mail_case, self._request(self.analyst), now=NOW).ai)
    # recreate, then disable
    ConnectorState.objects.filter(name="ai_model").update(enabled=False)
    rep = build_case_report(self.mail_case, self._request(self.analyst), now=NOW)
    self.assertIsNone(rep.ai)
    self.assertNotIn("AI model", [l.name for l in rep.case_connectors])

def test_low_tier_shows_runner_up(self): ...  # tier="low" → rep.ai["runner_up"] == {"result": "Safe"}

def test_group_case_never_gets_the_section(self): ...  # assessment row on a group case → rep.ai is None
```
- [ ] **Step 2: Run, expect FAIL** — `ww test backend api.tests.test_case_report_model`.
- [ ] **Step 3: Implement** `ai_connector_line` and the mail branch call in `build_case_report` (select the case with `select_related("ai_assessment", "campaign_membership__campaign")` in the views, Task 8; the builder does not re-query the case).
- [ ] **Step 4: Run, expect PASS** — `ww test backend api.tests.test_case_report_model`.
- [ ] **Step 5: Commit**
```bash
git add Suspicious/Suspicious/api/utils/case_report_model.py Suspicious/Suspicious/api/tests/test_case_report_model.py
git commit -m "feat(report): add the AI model assessment to mail case reports"
```

### Task 6: Markdown renderer

**Files:**
- Modify: `api/utils/case_report_markdown.py` (keep `_text`, `_code`, `_table`; replace `build_markdown_report`; `_health_line` logic moved to the model in Task 4, delete it here)
- Test: `api/tests/test_case_report_markdown_render.py` (new, `SimpleTestCase` on hand-built `CaseReport` objects)

**Interfaces:**
- Consumes: `CaseReport`, `IndicatorBlock`, `IndicatorRow`, `DetailGroup`, `ConnectorLine`, `LEGEND`, `band_icon`.
- Produces: `def build_markdown_report(report: CaseReport) -> str`. Layout: `# Case #<id>: <band>`; `**Verdict:** <icon> <band> · confidence <pct>`; `**Threat:**`; `**Analysis:** <health>`; lead; `Reporter / Case created / Report generated` (ISO); `## Description`; `## Reporter context`; `## Why this verdict` (case `why` lines); mail: `## AI model assessment` (class and sub-class, tier, runner-up on low, `Model <version> · analysed <iso>`, `Reads: body text only, not headers or attachments`, campaign line `Campaign <ref> · <size> mails` plus `labels` when present, cross-check facts and `AI and evidence disagree` when present); `## Case analyzers` (legend + connector bullets) when `case_connectors`; `## Case analysis` for file cases; `## Indicators` with legend, the table (`Value | Type | Verdict | Top finding`) when `rows`, then per block `### <TYPE> · <_code(value)>`, `Verdict: <icon> <band> · confidence <pct>`, `**Why this verdict**` bullets, `Found in … by …`, escalation note, `**Key findings**`, `**Details**` (`*Group*` then `- Label: value`), `VirusTotal: <link>` when `vt_link`, `**Connectors**` bullets `- <icon> <name>: <label>`; `+N more flagged indicators are listed in the table only.` when `more`; `No indicator observables on this case.` when kind is `none` or there are no rows and no blocks; footer `Generated by Suspicious. Screenshots are in the HTML report.`

- [ ] **Step 1: Failing tests**
```python
def test_block_layout(self):
    md = build_markdown_report(_report(blocks=[_block("ip", "203.0.113.7", "Dangerous", 87,
        findings=["2 of 91 VirusTotal engines flag it as malicious"],
        details=[DetailGroup("Location", [("Country", "NL")])],
        connectors=[ConnectorLine("🔴", "VirusTotal_GetReport_3_1", "2/91 detections", "malicious", 1)])]))
    self.assertIn("### IP · `203.0.113.7`", md)
    self.assertIn("Verdict: 🔴 Dangerous · confidence 87%", md)
    self.assertIn("- 🔴 VirusTotal_GetReport_3_1: 2/91 detections", md)
    self.assertIn("**Legend** " + LEGEND, md)
    self.assertNotIn("**Details**\n\n**Connectors**", md)

def test_empty_groups_and_fields_are_not_rendered(self):
    md = build_markdown_report(_report(blocks=[_block("hash", "a" * 64, "Safe", 40)]))
    for word in ("**Key findings**", "**Details**", "VirusTotal: http"):
        self.assertNotIn(word, md)

def test_indicator_value_and_details_are_escaped(self):
    v = "http://evil.test/`a`|b<script>alert(1)</script>[x](javascript:1)"
    md = build_markdown_report(_report(rows=[IndicatorRow("url", v, "Dangerous", "[y](javascript:2)")],
        blocks=[_block("url", v, "Dangerous", 90, details=[DetailGroup("Whois/RDAP", [("Registrar", "# Evil_ *Corp*")])])]))
    self.assertNotIn("](javascript", md)
    self.assertNotIn("<script>", md.replace("``", ""))   # only inside a code span
    self.assertFalse(any(l.startswith("# Evil") for l in md.splitlines()))
    table = [l for l in md.splitlines() if l.startswith("| ") and "evil.test" in l]
    self.assertEqual(table[0].count("|") - table[0].count("\\|"), 5)

def test_mail_ai_section(self):
    md = build_markdown_report(_report(kind="mail", ai={"result": "Unwanted", "sub_class": "spam", "tier": "low",
        "runner_up": {"result": "Safe"}, "model_version": "v3", "analysed_at": "2026-11-09T08:00:00Z",
        "reads": "body text only, not headers or attachments", "similar_cases": [], "campaign": None, "cross_check": None}))
    self.assertIn("## AI model assessment", md)
    self.assertIn("runner-up: Safe", md)
    self.assertIn("body text only, not headers or attachments", md)
    self.assertNotIn("Decisive rule", md)

def test_more_line_and_no_indicators(self):
    self.assertIn("+3 more flagged indicators", build_markdown_report(_report(kind="mail", more=3, rows=[...])))
    self.assertIn("No indicator observables on this case.", build_markdown_report(_report(kind="none")))
```
(`_text` leaves inner underscores alone, so the analyzer name appears unescaped.)
- [ ] **Step 2: Run, expect FAIL** — `ww test backend api.tests.test_case_report_markdown_render`.
- [ ] **Step 3: Implement** `build_markdown_report(report)`. Every value through `_text`/`_code`; icons and fixed labels are literals.
- [ ] **Step 4: Run, expect PASS** — `ww test backend api.tests.test_case_report_markdown_render` (`api.tests.test_case_report_markdown` is expected to fail until Task 8).
- [ ] **Step 5: Commit**
```bash
git add Suspicious/Suspicious/api/utils/case_report_markdown.py Suspicious/Suspicious/api/tests/test_case_report_markdown_render.py
git commit -m "feat(report): render the per-indicator case report as Markdown"
```

### Task 7: HTML template renderer

**Files:**
- Modify: `templates/case_report/report.html` (keep the `<style>` block, tokens, dark-mode and print rules; replace the body; drop the sources table, the per-source enrichment block and the raw `<details>`/`pprint`)
- Test: `api/tests/test_case_report_html_render.py` (new, `SimpleTestCase`, `render_to_string("case_report/report.html", {"report": rep})`)

**Interfaces:**
- Consumes: the `CaseReport` tree (Task 4/5), `LEGEND`. Template context is exactly `{"report": CaseReport, "legend": LEGEND}`.
- Produces: same sections and order as the Markdown (Task 6). Each block in a `.obs` card: heading `<TYPE> · value`, band pill (`band-{{ b.band }}`) with icon and `confidence N%`, "Why this verdict", "Key findings", "Details" as one small two-column table per group, `<a href>` VirusTotal link only when `b.vt_link` (already validated by the model), "Connectors" list; screenshot `<details><summary>Screenshot</summary><img …></details>` when `screenshot_data_uri`, the existing omitted note when `screenshot_omitted`; mail AI card; indicator table; `+N more` line; legend line.

- [ ] **Step 1: Failing tests**
```python
def test_html_block_has_type_specific_details_and_no_raw_output(self):
    html = render_to_string("case_report/report.html", {"report": _report(blocks=[_block("ip", "203.0.113.7", "Dangerous", 87,
        details=[DetailGroup("Location", [("AS owner", "Evil Hosting LLC")])],
        connectors=[ConnectorLine("🔴", "VirusTotal_GetReport_3_1", "42/70 detections", "malicious", 1)])]), "legend": LEGEND})
    self.assertIn("Evil Hosting LLC", html)
    self.assertIn("42/70 detections", html)
    self.assertIn("confidence 87%", html)
    self.assertNotIn("Raw report", html)
    self.assertNotIn("<pre>", html)

def test_html_escapes_values_and_links_only_virustotal(self):
    v = "http://evil.test/<script>alert(1)</script>"
    html = render(_report(blocks=[_block("url", v, "Dangerous", 90, vt_link="https://www.virustotal.com/gui/url/abc",
        details=[DetailGroup("URL", [("Final URL", "https://collect.test/x")])])]))
    self.assertNotIn("<script>alert(1)</script>", html)
    self.assertIn("&lt;script&gt;", html)
    self.assertEqual(re.findall(r'href="([^"]+)"', html), ["https://www.virustotal.com/gui/url/abc"])

def test_screenshot_is_collapsed(self):
    b = _block("url", "http://a.test", "Suspicious", 50); b.screenshot_data_uri = "data:image/png;base64,AAAA"
    html = render(_report(blocks=[b]))
    self.assertRegex(html, r"<details>\s*<summary>Screenshot</summary>\s*<img[^>]+data:image/png;base64,AAAA")

def test_mail_ai_card_and_table(self): ...  # "AI model assessment", "body text only, not headers or attachments",
    # indicator table row with "Dangerous", "+2 more flagged indicators", legend text present once

def test_no_safe_filter_in_template(self):
    src = Path(settings.BASE_DIR, "templates/case_report/report.html").read_text()
    for banned in ("|safe", "|pprint", "autoescape off"):
        self.assertNotIn(banned, src)
```
(Resolve the template path the way the project's `TEMPLATES` setting does; use `django.template.loader.get_template("case_report/report.html").origin.name` if `BASE_DIR` differs.)
- [ ] **Step 2: Run, expect FAIL** — `ww test backend api.tests.test_case_report_html_render`.
- [ ] **Step 3: Implement** the template. Reuse existing classes (`.summary`, `.pill.band`, `.obs`, `.sub`, `.empty`, `table`, `details`); add only what the new rows need (e.g. `.facts th { width: 30% }`, `.findings`).
- [ ] **Step 4: Run, expect PASS** — `ww test backend api.tests.test_case_report_html_render`.
- [ ] **Step 5: Commit**
```bash
git add Suspicious/Suspicious/templates/case_report/report.html Suspicious/Suspicious/api/tests/test_case_report_html_render.py
git commit -m "feat(report): render the per-indicator case report as HTML"
```

### Task 8: View wiring, old-layout tests, CHANGELOG and docs

**Files:**
- Modify: `api/views/case_report.py`
- Modify (tests pinning the old layout): `api/tests/test_case_report.py`, `api/tests/test_case_report_markdown.py`, `api/tests/test_case_report_verdict_explanation.py`, `api/tests/test_case_report_screenshot.py` (only if attribute access changes need it)
- Unchanged and must pass: `api/tests/test_case_report_permissions.py`, `api/tests/test_observable_report_derived.py`, `api/tests/test_investigation_reporter_context.py`, `api/tests/test_report_allow_list_fields.py`
- Modify: `CHANGELOG.md` (`## [Unreleased]` → `### Changed`), `docs/user-guide/soar-integration.md` (l.96), `docs/user-guide/investigations.md` ("Downloading the full report")

**Interfaces:**
- Consumes: `build_case_report(case, request, *, now) -> CaseReport`, `build_markdown_report(report) -> str`, the template.
- Produces: both views select the case with `submission_queryset(Case.objects.select_related("reporter", "fileOrMail__mail", "fileOrMail__file__linked_hash", "ai_assessment", "campaign_membership__campaign"), request.user)`, call `build_case_report(case, request, now=timezone.now())` once, and render. `_inline_screenshots(blocks: list[IndicatorBlock]) -> list[IndicatorBlock]` keeps its cap logic and name, switched to attribute access (`b.screenshot_url`, `b.screenshot_data_uri`, `b.screenshot_omitted`), applied to `report.blocks` (and `report.case_analysis` when set). `_collapse_sources` and its only test are deleted (the sources table is gone). Permissions, renderers, content types and filenames unchanged.

- [ ] **Step 1: Update the tests to the new layout (failing against the old views)**
  - `test_case_report.py::test_report_renders_enrichment`: replace `self.assertIn("42 / 70", body)` with `self.assertIn("42/70 detections", body)`; keep `"Evil Hosting LLC"` and `"trojan.emotet"` (now in the IP block's Location row and in Key findings `Threat name: trojan.emotet`); add `self.assertNotIn("Raw report", body)`.
  - `test_case_report_markdown.py`: keep every existing assertion except the table loop in `test_untrusted_text_cannot_make_links_or_break_tables`, replaced by: the VirusTotal connector line exists, contains `\[x\](javascript:alert(1)) \| pipe`, and `"[x](javascript"` is absent; add `test_markdown_has_block_skeleton` asserting `"### IP · `203.0.113.7`"`, `"**Connectors**"`, `"**Legend**"`; add `test_failed_source_line` asserting `"⚪ Shodan: failed"`.
  - `test_case_report_verdict_explanation.py`: `test_report_falls_back_to_verdict_rationale` now asserts `"<li>Two tier-2 sources disagree.</li>"` inside the case "Why this verdict" (drop `assertNotIn("Why this verdict")`, blocks carry the heading too); replace `test_report_collapses_duplicate_sources` with `test_explanation_sources_are_not_listed`: 1400 duplicate `Mail_Header_Analyzer_1_0` rows give `body.count("Mail_Header_Analyzer_1_0") == 0` and the analyst paragraph is shown.
  - New in `test_case_report.py`: `test_mail_case_report_lists_embedded_indicators` (mail case via `CaseHasFileOrMail`, embedded URL with a malicious tier-1 report → HTML and Markdown contain the URL, `"Dangerous"`, and no `"No indicator observables"`); `test_reporter_download_has_no_cross_check` (mail case with assessment, connector on, reporter downloads `.md` → `"AI model assessment"` present, `"Decisive rule"` absent; CERT analyst on the same case → present).
- [ ] **Step 2: Run, expect FAIL** — `ww test backend api.tests.test_case_report api.tests.test_case_report_markdown api.tests.test_case_report_verdict_explanation`.
- [ ] **Step 3: Implement** the view changes above. Docs: soar-integration l.96 and investigations "Downloading the full report" describe the per-indicator blocks (verdict, why, key findings, type-specific details, connectors, legend), mail and file evidence, the AI section for mail cases, screenshots collapsed in HTML only, no raw analyzer output. CHANGELOG `### Changed` entry: "Case report (HTML and Markdown) redesigned: one block per indicator with type-specific details (location, Whois/RDAP, categorization, URL, hash, VirusTotal), key findings and a connector summary ordered by severity with a legend; mail and file cases now show their indicators and analyzers, mail cases the AI model assessment; raw analyzer output is no longer embedded."
- [ ] **Step 4: Run, expect PASS** — `ww test backend api.tests.test_case_report api.tests.test_case_report_markdown api.tests.test_case_report_verdict_explanation api.tests.test_case_report_screenshot api.tests.test_case_report_permissions api.tests.test_observable_report_derived api.tests.test_report_facts api.tests.test_case_report_model api.tests.test_case_report_markdown_render api.tests.test_case_report_html_render`, then the whole app: `ww test backend api`.
- [ ] **Step 5: Commit**
```bash
git add Suspicious/Suspicious/api/views/case_report.py Suspicious/Suspicious/api/tests/test_case_report.py \
  Suspicious/Suspicious/api/tests/test_case_report_markdown.py Suspicious/Suspicious/api/tests/test_case_report_verdict_explanation.py \
  Suspicious/Suspicious/api/tests/test_case_report_screenshot.py CHANGELOG.md \
  docs/user-guide/soar-integration.md docs/user-guide/investigations.md
git commit -m "feat(report): serve the redesigned per-indicator case report"
```

## Self-review

**Spec coverage.**
- Goal 1 (same skeleton, type-specific details): Task 3 `detail_groups` + `GROUPS_BY_TYPE`; Tasks 6/7 skeleton.
- Goal 2 (hide empties, caps, no raw output): Task 3 caps and empty-dropping; Task 7 drops `pprint`; Task 8 asserts `Raw report` gone.
- Goal 3 (mail and file evidence): Task 4 collectors (`assemble_mail_observables`, `assemble_file_observable`, `file_reports`).
- Goal 4 (one model, two renderers): Task 4 model; Tasks 6/7 render only.
- Goal 5 (legend, severity-ordered connectors): Task 3 constants and `connector_lines`.
- Field sources (VT per type, enrichment first, link): Task 1. Fallbacks DShield/SFS/Zscaler: Task 2. Mnemonic rDNS, URLScan, MaxMind, Abuse_Finder, CrowdSec: excluded per spec (only as connector lines).
- Rules (dates, ages only in findings, connector order and labels, key-finding candidates, escaping, screenshots collapsed and capped, no network requests): Tasks 1, 3, 6, 7, 8.
- Why this verdict (case explanation fallback chain, per-indicator rationale, no AI text): Task 4 `why` fields.
- AI model assessment (conditions, payload fields, reporter vs analyst, connector line, Cortex AI excluded): Tasks 4 and 5, rendered in 6/7, end-to-end in 8.
- Calls made (indicator sources, mail address row without block, file "Case analysis", verdict words, header elements kept, sources table dropped, data per section): Tasks 4, 6, 7, 8.
- Constraints (permissions, URLs, content types unchanged; old tests updated; screenshot cap and permission tests kept; no per-row query): Task 8; Task 4 `test_query_count_does_not_grow_with_indicators`.

**Type consistency.** Source dicts keep the `assemble_observables` shape (`name, tier, verdict, confidence, evidence, failed, enrichment, report`) from Task 2 onward; `IndicatorFacts` is produced in Task 1, refined in Task 2, consumed in Task 3; `DetailGroup` and `ConnectorLine` are defined in Task 3 and used unchanged by Tasks 4-7; `CaseReport.confidence` is a preformatted string, `IndicatorBlock.confidence` an int formatted by the renderers with the same `round` rule; dates are strings from `iso_utc` everywhere, so renderers never format dates.

**Proportion.** Two new modules (pure facts, model+collectors), two renderers rewritten in place, two additive collector functions plus one helper extraction; no new models, migrations, settings or dependencies. Rules and thresholds beyond the spec are the minimum the key-finding candidates need (30 days, rank ≤ 1000).

**Interpretations the owner may overrule:** group cases render every indicator as a block (up to 10) rather than only Dangerous/Suspicious, so a single Safe IP case still shows its evidence; the legend appears once per section rather than once per block; RDAP and StopForumSpam nesting are read tolerantly because no real payload is in the repo.
