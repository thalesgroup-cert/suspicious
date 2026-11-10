# Case report redesign (per-indicator, per-type)

Status: draft for review, 2026-11-10. Nothing built. Replaces the layout of the downloadable
case report (HTML `GET /api/cases/<id>/report/`, Markdown `GET /api/cases/<id>/report.md`).

## Intent

The report is read by an analyst or a reporter who wants to know, per indicator, what it is, why it
got its verdict, and the few facts that matter, without scrolling through raw analyzer output.
Today every indicator gets the same layout (a sources table plus a few enrichment counts), mail and
file cases show no indicator evidence at all, and the HTML dumps each source's raw output.

Goal: one short, scannable block per indicator whose fields depend on its type, built only from
data Suspicious already stores.

## Goals

1. A block per indicator with the same skeleton for every type and type-specific details.
2. Show a field only when it has a value; cap long lists; no raw analyzer output.
3. Mail and file cases get an evidence section for their embedded indicators.
4. HTML and Markdown carry the same content from one data model, rendered twice.
5. A legend, and a connector summary ordered by severity.

## Non-goals

- No new analyzers or connectors, and no change to scoring or verdicts.
- No generated AI text in v1 (see "Why this verdict").
- No URLScan, MaxMind GeoIP, Abuse_Finder, CrowdSec or reverse-DNS analyzer data: on the owner's
  prod their stored `report_full` is only a placeholder (`{"ongoing": ...}`), so there is nothing to
  show. Their sections appear when those analyzers store real output.
- No change to who may download a report.

## Block layout (Markdown; the HTML mirrors it)

```
# <TYPE> · <value>
Verdict: 🔴 Malicious · confidence 87%

**Why this verdict**
2-4 lines.

**Key findings**
- 3-5 bullets, strongest facts first

**Details**   (only the groups that apply and have values)
Location · Whois/RDAP · Hash · Categorization · VirusTotal · URL

**Connectors**
- 🔴 VirusTotal: 2/91 detections
- 🟠 Zscaler: Phishing
- 🟢 SpamhausDBL: not listed
- ⚪ Urlscan: no data

**Legend**  🔴 malicious  🟠 suspicious  🟢 safe  ⚪ failed / unknown
```

Case page: a header (case id, result, confidence, reporter, dates), the existing description and
reporter context, then one block per indicator, malicious first.

Types and their detail groups:

| Type | Groups shown |
|---|---|
| IP | Location, Whois/RDAP, Categorization (if any), VirusTotal |
| Domain | Location (resolved IPs), Whois/RDAP, Categorization, VirusTotal |
| URL | URL (final URL, redirects, title, HTTP code, brands), Location (if any), Categorization, VirusTotal |
| Hash / file | Hash, VirusTotal (AV and sandbox vendors) |

Mail and file cases: the case header, then a table of embedded indicators (value, type, verdict,
top finding) ordered by severity. Only malicious and suspicious indicators get a full block
(at most 10, the rest are in the table with a "+N more" line).

## Field sources (verified against the owner's prod `report_full` keys on 2026-11-10 and the
VirusTotal v3 reference; every field is optional)

VirusTotal (`VirusTotal_GetReport_3_1`, keys are the VT attributes flattened into `report_full`):

- All types: `last_analysis_stats` (detections as `malicious/total`), `last_analysis_results`
  (names of malicious and suspicious engines, at most 10 then "+N more"), `reputation`, `tags`,
  `total_votes`, `threat_severity`.
- Domain: `registrar`, `creation_date`, `last_update_date`, `rdap` (registrant, entity emails and
  phone, name servers, status, event dates), `whois` (raw text, fallback only), `categories`
  (vendor to category), `popularity_ranks` (for example Cisco Umbrella rank), `last_dns_records`
  (A and AAAA values give the resolved IPs).
- IP: `country`, `continent`, `asn`, `as_owner`, `network`, `regional_internet_registry`, `rdap`,
  `whois` (fallback).
- URL: `last_final_url`, `title`, `last_http_response_code`, `categories`, `web_category`,
  `threat_names`, `identified_brands` and `main_brand`, `first_submission_date`,
  `times_submitted`, `outgoing_links` (count only).
- Hash/file: `first_submission_date`, `last_submission_date`, `last_analysis_date`,
  `meaningful_name`, `names`, `type_description`, `size`, `md5`/`sha1`/`sha256`, `sandbox_verdicts`
  (vendor to verdict), `popular_threat_classification` if present. Unverified: the VT hash sample
  available was "not found", and the VT reference page does not list the threat classification.
- The VirusTotal link is built from the indicator and type.
- The existing `AnalyzerReport.enrichment` (the one VirusTotal extractor) is used where it already
  has the value; the rest is read from `report_full`.

Other sources seen in prod: Zscaler `urlClassifications` and `urlClassificationsWithSecurityAlert`
(categorization and a malicious flag), DShield (`asname`, `ascountry`, `asabusecontact`, `network`,
`attacks`, `reputation`, `threatfeeds`), StopForumSpam (`asn`, `country`, `appears`), SpamhausDBL
(`classification`), Google Safe Browsing (`results`), PhishTank (`in_database`), MISP
(`results`: event count and titles), Mnemonic passive DNS (`findings`: names an IP resolved to,
shown as reverse-DNS names), SPF/DMARC (`DomainMailSPFDMARC`), CIRCL hashlookup, Mail_Header
analyzer for mail cases.

## Rules

- Hide any empty field, any empty group, and any group that does not apply to the type.
- Lists: reverse-DNS and resolved names at most 5 plus "and N more"; malicious vendors at most 10
  plus "+N more"; name servers all (they are few).
- Dates as UTC ISO 8601 (`2026-09-27T22:06:27Z`); ages ("registered 3 days ago") only inside Key
  findings.
- Connector summary: one line per analyzer that ran for the indicator (the newest report per
  analyzer, as `assemble_observables` does today). Icon from the source's verdict: malicious 🔴,
  suspicious 🟠, clean 🟢, no-data or failed ⚪. Order 🔴, 🟠, 🟢, ⚪, then by tier, then name.
  Label: VirusTotal `m/total detections`, otherwise the source's evidence text.
- Key findings come from a small fixed rule list over the facts, not from a model. Candidates:
  detections above zero, domain younger than 30 days, a brand impersonation (identified brand not
  matching the domain), a redirect to another host, a blocklist or MISP hit, a top popularity
  rank, a threat name. Each rule needs its input fact; no fact, no bullet.
- Every external value goes through the existing Markdown escaping (`_text`, `_code`); the HTML
  keeps Django autoescaping. Raw analyzer output is not rendered.
- Screenshots stay out of Markdown. In HTML they sit inside a collapsed `<details>` under the
  existing 6 MiB total cap. Network requests are not shown: no stored source has them.

## Why this verdict

v1 uses what exists: the case's rule-based explanation (`verdict_explanation` analyst paragraph,
else `verdict_rationale`, else `inconclusive_reason`) and, per indicator, the observable verdict's
`rationale` lines. The `ai_narration` connector only logs its text and nothing persists it, so an
AI paragraph is a later step: persist the narration per case, then show it here when present. The
section title stays "Why this verdict" so that step needs no layout change.

## Constraints

- Permissions, URLs and the HTML/Markdown content types do not change.
- Existing tests that pin the old layout (for example the exact string `42 / 70`, section names and
  the screenshot cap) are updated or replaced. The screenshot cap and the permission tests stay.
- One module builds a plain data model (dataclasses) from a case; the HTML template and the
  Markdown builder only render it. No query per row: reuse the single report query of
  `observable_reports`.
- Report size stays bounded by the caps above; no raw dumps.

## AI model assessment (mail cases)

Mail cases get an "AI model assessment" section after the case header and before the indicators. It
is the payload the case drawer already shows, built with `ai_model.presentation.present_assessment`
for the person downloading the report, so a reporter sees exactly what the UI shows them and an
analyst sees the extra cross-check. It appears only while the `ai_model` connector is enabled and
the case has an assessment; otherwise there is no section (historical Cortex AI reports stay out,
as in the weighted blend).

What the section shows, from that payload:
- Class and sub-class (`result`, `sub_class`), the confidence tier (High, Medium or Low) and, on a
  Low tier, the runner-up class.
- Model version and when it analysed the mail (`model_version`, `analysed_at`).
- The input note: "body text only, not headers or attachments", so nobody reads it as a verdict on
  the attachments.
- The campaign line when the case is in a campaign: reference, size and, for analysts, the folder
  labels of members; similar cases only as far as the viewer may see them.
- Analysts only: the cross-check facts (decisive rule, independent sources, list matches) and
  whether the AI and the evidence disagree.

The AI vote also appears as a line in the case-level connector list ("🟠 AI model: Suspicious,
High confidence"), using its class and tier, next to the mail-header and file analyzers.

## Calls made after the builder check (the owner can overrule any)

- **Where indicators come from.** Group cases use `observable_reports(case)` as today. Mail cases
  use `mail_observable_reports(mail)` (embedded URL, IP, hash, domain and mail-address
  artifacts, one query for the mail); the per-indicator verdict comes from the same
  `score_observable` engine over those reports. A mail address gets a row in the indicator table
  and no full block (the data holds nothing worth a block). A file case has no embedded
  indicators: its own hash and file analyzers are shown as the case's "Case analysis" block (a
  Hash block plus the connector list). One data model, two collectors.
- **Verdict words.** The case and indicator bands keep the app's names: 🔴 Dangerous,
  🟠 Suspicious, 🟢 Safe, ⚪ Inconclusive. Connector lines use the connector vocabulary (malicious,
  suspicious, safe, failed or unknown) with the same four icons; the legend lists both words
  where they differ ("malicious / dangerous"). Confidence is shown as a percentage, rounded the
  way the current report rounds it. "Malicious first" means Dangerous, then Suspicious, Safe,
  Inconclusive; only Dangerous and Suspicious indicators get a full block.
- **Case-level elements.** The header keeps the threat classification, the analysis-health line
  ("N analyzers failed or still running") and the reporter lead paragraph. "Why this verdict" at
  case level is the analyst paragraph plus the confidence reading, as today. The collapsed
  sources table is dropped: each indicator's connector list replaces it, and mail and file cases
  get the same connector list for their case-level analyzers.
- **Other sources.** VirusTotal fills the Details groups first. When it has no value, fallbacks
  fill: DShield or StopForumSpam for IP location (country, ASN, AS name, network), Zscaler for
  Categorization (URL, domain, IP). Every other source appears only as a connector line and,
  for blocklist or MISP hits, in Key findings. Reverse-DNS names from Mnemonic passive DNS are
  not in v1: the payload shape of `findings` is unverified.
- **Data per section.** Details are built per group from the newest report of each source; with
  no VirusTotal report and no fallback, the group is hidden and the block says nothing about it.
  A failed or missing source only changes its connector line.

## Left to the builder

Names of modules and dataclasses, the exact wording of key findings and rule thresholds beyond
those above, the HTML styling (reuse the existing inline CSS, dark mode and print rules), whether
a missing optional key is read through one small accessor, and the fixtures (built from the real
key shapes above, with made-up values).

## Open items

- Why several analyzers (Urlscan, MaxMind, Abuse_Finder, CrowdSec, GoogleDNS) store only a
  placeholder is a separate investigation; fixing it would add data to this report later.
- The unverified VirusTotal hash fields need one real "found" payload from prod before they are
  trusted; the code treats them as optional.
