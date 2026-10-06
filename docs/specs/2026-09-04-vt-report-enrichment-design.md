# VT Report Enrichment — Design

**Status:** draft, awaiting review
**Date:** 2026-09-04
**Author:** Theo Bhang (with Claude)
**Branch base:** `impl/ioc-analysis-road` tip (`d1920cdc`), or `design/ioc-road-and-verdict-model` once the IOC-road branch is merged — this work sits on top of the IOC-road + categorical-scoring changes and touches files both modified.

---

## 1. Motivation

The Sept 2026 SOC feedback (Marie/MION, Julien/GROCH + 2 analysts) converges on
one theme: **"sortir de l'effet boîte noire."** The concrete P1 asks:

- verdict quality with more weight on GTI / VirusTotal
- threat classification (what *kind* of malware / phishing)
- show which vendors flagged the indicator as malicious
- ISP / geo for IPs
- VT first- and last-submission dates
- hash ↔ filename mapping

Every one of these data points is **already stored** in
`AnalyzerReport.report_full` for VT-analyzed observables — Cortex's
`VirusTotal_GetReport_3_1` writes the full VT v3 JSON. Suspicious just never
parses past `last_analysis_stats` (`contrib/virustotal.py` reads only
`malicious` / `total`). The sibling project `~/vt_tool`
(`app/services/virustotal_service.py`) already has the exact field extraction —
written against the `vt` SDK's object attributes, so it needs re-pointing at the
raw JSON dict, not re-inventing.

This design delivers the extraction, surfaces it on both investigation roads
(mail and IOC), and — per the review decision of 2026-09-04 — **also refines the
VT verdict** so a lone low-quality engine detection stops producing a
`malicious` band (the `8.8.8.8` / `auth.users.pub` class of false positive).

## 2. Scope

**In:**
- A VT field-extraction module producing a flat, display-ready dict.
- A new nullable `AnalyzerReport.enrichment` JSONField, written by the parser.
- Refined `level` / `confidence` determination in the VT parser using the
  extracted fields. **VT parser only** — no change to the categorical engine,
  the mail `score_case`, tiers, or any non-VT analyzer.
- API exposure on both roads.
- Shared frontend components rendering the enrichment.
- A backfill management command for historical reports.

**Out (explicitly not in this chunk):**
- New analyzers (Shodan / AbuseIPDB / Hybrid Analysis) — the extraction
  `registry` is built so they slot in later with the same contract, but wiring
  them is separate work.
- URL-page screenshot capture.
- Changes to GTI parsing (GTI already lands `threat_score` → band correctly).
- Per-case verdict rationale text overhaul (separate roadmap chunk).
- Exportable ticket format / bulk SOAR endpoint (separate roadmap chunk).

## 3. Data model

### 3.1 `AnalyzerReport.enrichment`

```python
enrichment = models.JSONField(null=True, blank=True, default=None)
```

- Additive, nullable. Migration `cortex_job/migrations/0013_analyzerreport_enrichment.py`
  (cortex_job's tip on this branch is `0012_seed_analyzer_tiers`).
- `None` = not extracted (historical report, or analyzer with no extractor, or
  extraction failed / returned nothing).
- `{}` is never written — extractors return `None` when there is nothing useful.
- Written by `create_and_save_report` in the same `save(update_fields=[...])`
  that already writes `score` / `confidence` / `category` / `level` — one extra
  field, no extra query.

### 3.2 Enrichment dict shape

A flat dict, all keys optional (absent when the source lacks the field). Values
are JSON scalars or short lists — never the raw nested VT structure.

```python
# common to all observable types
{
  "source": "virustotal",              # which extractor produced this
  "vendors": [                          # from last_analysis_results, sorted: flagging first
    {"name": "Kaspersky", "category": "malicious", "result": "Trojan.Win32.Emotet.a"},
    {"name": "ESET-NOD32", "category": "malicious", "result": "a variant of Win32/Kryptik"},
    {"name": "Microsoft", "category": "undetected", "result": None},
    ...
  ],
  "malicious_count": 42,
  "suspicious_count": 3,
  "total": 70,
  "reputation": -14,                    # VT community reputation, -100..100
  "first_seen": "2019-01-03T08:12:44Z", # first_submission_date (ISO 8601, UTC)
  "last_seen": "2026-08-30T11:02:10Z",  # last_analysis_date or last_submission_date
  "tags": ["emotet", "cve-2017-11882"],
  "vt_link": "https://www.virustotal.com/gui/file/<sha256>",
}

# ip observables additionally
{
  "as_owner": "Google LLC",
  "asn": 15169,
  "country": "US",
  "continent": "NA",
  "network": "8.8.8.0/24",
}

# domain / url observables additionally
{
  "registrar": "MarkMonitor Inc.",
  "creation_date": "1997-09-15T04:00:00Z",
  "categories": {"Forcepoint ThreatSeeker": "search engines and portals"},
  "final_url": "https://example.com/landing",   # url only
  "page_title": "Sign in",                       # url only
}

# hash / file observables additionally
{
  "meaningful_name": "invoice_2026.exe",
  "names": ["invoice_2026.exe", "8f3a...bin", "payload.dll"],  # capped at 10
  "size": 245760,
  "type_description": "Win32 EXE",
  "threat_category": "trojan",                   # popular_threat_classification.popular_threat_category[0].value
  "threat_label": "trojan.emotet/heur",          # popular_threat_classification.suggested_threat_label
}
```

Frontend and the report template treat any missing key as "not available" — no
sentinel strings (vt_tool's `"Not found"` convention is **not** carried over;
absent means absent).

## 4. Extraction module — `score_process/scoring/enrichment/`

New package. No ORM access — pure `dict -> dict` translation, like
`scoring/sources.py`.

### 4.1 `enrichment/virustotal.py`

```python
def extract(report_full: Any, data_type: str) -> Optional[dict]:
    """Pull the display-ready fields from a VirusTotal v3 report_full.
    Returns None when report_full carries no usable VT attributes."""
```

- **Attribute location**, defensive (mirrors `contrib/virustotal.py::_stats`):
  1. `report_full["results"]["data"]["attributes"]` — Cortex v3 nesting
  2. `report_full["results"]["attributes"]` — flatter variant
  3. `report_full["results"]` itself, if it has `last_analysis_results`
  4. legacy `report_full["results"]` with `positives` / `total` / `scans` —
     produce `vendors` from `scans` (`{engine: {detected, result}}`), no
     type-specific fields.
  Return `None` if none match.
- **`vendors`**: `last_analysis_results` is `{engine: {category, result, engine_name, ...}}`.
  Map to `{"name": engine, "category": category, "result": result or None}`.
  Sort: `malicious` → `suspicious` → `type-unsupported` → `harmless`/`undetected`,
  then alphabetical within a group. Legacy `scans`: `{engine: {detected, result}}`
  → `category = "malicious" if detected else "undetected"`.
- **`malicious_count` / `suspicious_count` / `total`**: from `last_analysis_stats`
  if present, else counted from `vendors`.
- **dates**: VT gives unix timestamps. Convert to ISO 8601 UTC (`Z` suffix).
  `first_seen` ← `first_submission_date`. `last_seen` ← `last_analysis_date`
  falling back to `last_submission_date`. Absent / `0` → key omitted.
- **`vt_link`**: build from `data_type` + the observable id:
  - hash/file → `https://www.virustotal.com/gui/file/<sha256 or the value>`
  - ip → `/gui/ip-address/<ip>`
  - domain → `/gui/domain/<domain>`
  - url → `/gui/url/<url_id>` where `url_id` is the VT base64 of the URL
    (compute inline — `base64.urlsafe_b64encode(url.encode()).rstrip(b"=")`; no
    `vt` SDK dependency).
  The observable value is passed in by the caller (see 4.3) since `report_full`
  does not always echo it.
- **type-specific blocks**: guard every `attributes.get(...)`; a `TypeError` /
  `KeyError` anywhere returns whatever was extracted so far (never raises).
- **`names`** capped at 10; **`vendors`** not capped (the frontend paginates).

### 4.2 `enrichment/registry.py`

```python
_EXTRACTORS = {
    # matched against analyzer.name (lowercased, substring)
    "virustotal": ("virustotal", virustotal.extract),
}

def enrich(report) -> Optional[dict]:
    """Dispatch on report.analyzer.name → the right extractor, or None."""
```

- Match on `report.analyzer.name.lower()` containing a key
  (`"virustotal_getreport_3_1"` contains `"virustotal"`). GTI's analyzer name
  contains `"googlethreatintelligence"` — deliberately **not** matched here;
  GTI enrichment is a later addition if wanted.
- The extractor is called with `(report.report_full, report.type,
  observable_value)`; `registry.enrich` resolves `observable_value` from the
  report's non-null FK (`report.ip.address` / `report.hash.value` / …) the same
  way `InvestigationAnalyzerReportSerializer.get_target` does — hoist that FK
  walk into a new shared helper
  `cortex_job/cortex_utils/report_target.py::analyzer_report_target_value(report) -> str | None`,
  and refactor `get_target` to call it.
- Wrap the extractor call in `try/except Exception` → log + return `None`.
  Enrichment is never allowed to break scoring.

### 4.3 Wiring into `create_and_save_report`

`score_process/scoring/cortex_analyzers/reports.py::create_and_save_report`,
after the parser produces its `result_dict` and before `report.save`:

```python
from score_process.scoring.enrichment.registry import enrich
report.enrichment = enrich(report)          # None on any failure
report.save(update_fields=["score", "confidence", "category", "level", "enrichment"])
```

The VT parser (4.4) *also* needs the extraction; to avoid computing it twice,
`create_and_save_report` computes `enrich(report)` once and passes it into the
parser via a new optional `parser.run(summary, full, status, enrichment=...)`
kwarg (default `None` → parser extracts its own if it wants it). Parsers that
ignore enrichment are unaffected.

## 5. Verdict refinement — `contrib/virustotal.py` only

### 5.1 Current behaviour

```python
if malicious > 0:      level = "malicious"
elif suspicious > 0:   level = "suspicious"
else:                  level = "safe"
score, confidence = get_level_score_confidence(level)   # flat 4-row lookup
```

`get_level_score_confidence("malicious") == (10, 100)` regardless of whether
1 or 60 engines flagged.

### 5.2 Refined behaviour

Using the enrichment dict (`malicious_count`, `suspicious_count`, `total`,
`reputation`, `threat_label`):

```
threat_class = bool(enrichment.get("threat_label") or enrichment.get("threat_category"))

if malicious_count >= 2 or (malicious_count >= 1 and threat_class):
    level = "malicious"
elif malicious_count == 1 or suspicious_count >= 2 or (reputation <= -25 and malicious_count == 0):
    level = "suspicious"
else:
    level = "safe"
```

Confidence scales with vendor agreement instead of the flat constant:

```
if level == "malicious":
    confidence = clamp(round(50 + 45 * malicious_count / max(total, 1)), 55, 95)
elif level == "suspicious":
    confidence = 60
else:  # safe
    confidence = 90 if total >= 10 else 60      # few engines scanned → less sure it's clean
```

`score` stays tied to `level` via `get_level_score_confidence`'s score column
(malicious 10 / suspicious 7 / safe 0) — the number is not the surface the SOC
reads, the band + vendor ratio is.

If the enrichment dict is `None` (extraction failed), fall back to the **current**
behaviour verbatim — no regression on the unparseable case.

### 5.3 How this reaches each road

- **IOC road:** `source_verdict_from_report` maps `report.level` →
  `SourceVerdict.verdict` (`malicious`→`malicious`, `suspicious`→`suspicious`,
  `safe`→`clean`). A tighter `level` from the VT parser flows straight through.
  No change to `sources.py` or `observable_engine.py`.
- **Mail road:** `process_ioc` / `process_mail_artifact` build `Signal`s from
  `report.score` + `report.confidence`. A refined confidence flows straight
  through `_signals_from` → `score_case`. No change to `collect.py` or
  `engine.py`.

### 5.4 Validation gate

- New fixture set `score_process/scoring/cortex_analyzers/fixtures/virustotal/`:
  each file `{"report_full": {...}, "data_type": "...", "expect": {"level": "...",
  "confidence_min": N, "confidence_max": N}}` where `report_full` is a realistic
  VT v3 payload. Minimum cases:
  - `ip_8888_clean.json` — 0/90 detections, benign → `safe`, high conf
  - `ip_lone_fp.json` — 1/88 detections, no threat class → `suspicious` (was
    `malicious`)
  - `hash_emotet.json` — 55/70 + `popular_threat_classification` → `malicious`,
    conf ≥ 90
  - `url_two_engines.json` — 2/78, no class → `malicious`, conf ~53→clamped 55
  - `domain_neg_reputation.json` — 0 detections, reputation −40 → `suspicious`
  - `legacy_positives.json` — old `{positives, total}` shape → current fallback
- `pytest`-style `test_virustotal_enrichment.py` + `test_virustotal_verdict.py`.
- `manage.py backtest_scoring --road all` — no band change on any historical
  case that isn't a VT lone-FP (document expected diffs).
- `manage.py score_accuracy` — the 5 labelled cases stay green (they carry
  pre-computed `SourceVerdict`s, so unaffected, but run it to be sure).

## 6. API

### 6.1 Mail road — `InvestigationAnalyzerReportSerializer`

Add `"enrichment"` to `Meta.fields`. It is a plain model field (`JSONField`),
no `SerializerMethodField` needed. This is also the first time the VT vendor
list / dates / geo reach the mail-road frontend at all (the serializer ships
`report_summary` + `report_taxonomy` but never `report_full`).

### 6.2 IOC road — `api/utils/observable_report.py::assemble_observables`

Each `sources[]` dict gains `"enrichment": rep.enrichment`. `full=False` (detail
API) and `full=True` (downloadable report) both include it — it is already
compact.

### 6.3 Downloadable report template

`templates/case_report/report.html` — render the enrichment block per source:
threat label, first/last seen, AS owner + country (ip), filenames (hash), and a
"N / M vendors flagged" line with the flagging vendors listed. Autoescaped as
everything else in that template.

## 7. Frontend — `suspicious-ui/src/features/investigation/`

### 7.1 `enrichment.ts`

Zod schema + `type Enrichment = z.infer<...>`, mirroring §3.2. All fields
`.optional()`. `parseEnrichment(x: unknown): Enrichment | undefined` — `console.warn`
on a present-but-invalid payload (same pattern as `parseObservableGroup` after
follow-up #5).

### 7.2 `<AnalyzerEnrichment enrichment={Enrichment} />`

Prop-driven, road-agnostic. Two sub-parts:

- **`<FactGrid>`** — a compact key/value grid, only rows with a value:
  AS owner · country · ASN · network (ip); registrar · created · final URL ·
  page title (domain/url); filename(s) · size · type · threat label (hash);
  first seen · last seen · reputation · tags (all).
- **`<VendorTable>`** — MUI `<Table size="small">`, columns *Vendor · Verdict ·
  Result*. Defaults to **flagging vendors only** (`category` in
  `{malicious, suspicious}`) with a header line
  `"{malicious_count} / {total} security vendors flagged this"` and a
  `"show all N"` toggle. Verdict `<Chip>` colour: malicious→error,
  suspicious→warning, harmless/undetected→default. Virtualise / cap at ~200 rows
  if "show all" and the list is huge.
- A "View on VirusTotal" link (`vt_link`) when present — `target="_blank"
  rel="noopener"`.

### 7.3 Render sites

- **IOC road:** inside `SourceTable`'s existing detail `<Accordion>`, above the
  raw-JSON `<pre>`. Only when `source.enrichment` is present.
- **Mail road:** inside `InvestigationAnalyzerReportCard`, a new
  `<Accordion>` "Enrichment" section next to the existing "Summary JSON" /
  "Taxonomy JSON" ones. Only when `report.enrichment` is present.

### 7.4 Tests

- `enrichment.test.ts` — schema parse of a full fixture + a sparse one.
- `AnalyzerEnrichment.test.tsx` — renders the fact grid, the flagging-only
  default, the "show all" toggle, the threat-label chip.

## 8. Backfill — `manage.py backfill_enrichment`

```
manage.py backfill_enrichment [--dry-run] [--analyzer virustotal] [--limit N]
```

- Iterates `AnalyzerReport` rows where `enrichment IS NULL` and
  `status == "Success"` and the analyzer has an extractor.
- Runs `registry.enrich(report)`, writes `enrichment` only (no re-scoring — the
  verdict refinement applies to *new* analyses; a separate
  `backtest_scoring`-style re-score is out of scope here).
- Batched (`iterator()` + `bulk_update` in chunks of 500), idempotent,
  `--dry-run` prints counts only.

## 9. File-by-file summary

| File | Change |
|---|---|
| `cortex_job/models.py` | `+ enrichment` JSONField |
| `cortex_job/migrations/0028_analyzerreport_enrichment.py` | new, additive |
| `cortex_job/cortex_utils/report_target.py` | new — `analyzer_report_target_value(report)` (hoisted from the serializer's `get_target`) |
| `score_process/scoring/enrichment/__init__.py` | new |
| `score_process/scoring/enrichment/virustotal.py` | new — `extract()` |
| `score_process/scoring/enrichment/registry.py` | new — `enrich()` |
| `score_process/scoring/cortex_analyzers/base.py` | `run()` gains `enrichment=None` kwarg, threaded to `parse()` |
| `score_process/scoring/cortex_analyzers/reports.py` | `create_and_save_report` computes + persists `enrichment`; passes it to `parser.run` |
| `score_process/scoring/cortex_analyzers/contrib/virustotal.py` | refined `level`/`confidence` from enrichment; current behaviour as fallback |
| `score_process/scoring/cortex_analyzers/fixtures/virustotal/*.json` | new fixture set |
| `score_process/tests/test_virustotal_enrichment.py`, `test_virustotal_verdict.py` | new |
| `api/serializers/investigations.py` | `+ "enrichment"` in `InvestigationAnalyzerReportSerializer.Meta.fields`; `get_target` FK-walk → shared helper |
| `api/utils/observable_report.py` | `sources[]` dict `+ "enrichment"` |
| `api/tests/test_investigation_group.py`, `test_case_report.py` | enrichment assertions |
| `templates/case_report/report.html` | enrichment block per source |
| `suspicious-ui/src/features/investigation/enrichment.ts` | new |
| `suspicious-ui/src/features/investigation/AnalyzerEnrichment.tsx` | new (+ `FactGrid`, `VendorTable`) |
| `suspicious-ui/src/features/investigation/SourceTable.tsx` | render `<AnalyzerEnrichment>` |
| `suspicious-ui/src/features/investigation/components/InvestigationAnalyzerReportCard.tsx` | render `<AnalyzerEnrichment>` |
| `suspicious-ui/src/features/investigation/api.ts` | `enrichment?` on `InvestigationAnalyzerReport` + `normalize` |
| `suspicious-ui/src/features/investigation/__tests__/…` | new |
| `score_process/management/commands/backfill_enrichment.py` | new (alongside `backtest_scoring` / `score_accuracy`) |

## 10. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Verdict change causes unexpected band shifts on live cases | VT-only; new fixtures pin the intended shifts; `backtest_scoring --road all` diff reviewed before merge; refined rule only *tightens* (fewer `malicious`), so it can't introduce new false negatives beyond the lone-1-engine case, which is the point |
| Cortex VT JSON shape differs from assumed v3 nesting | Extractor tries 4 shapes then returns `None`; `None` → current parser behaviour; a real sample from the live instance is pulled during implementation (spec §5.4 first task) |
| `enrichment` bloats the investigation payload for a 100-IOC case | vendor list is the only large part; it is already smaller than the `report_full` we currently ship on the IOC road's `full=True` path, and the mail road gains it in place of nothing |
| Backfill locks the table | `iterator()` + chunked `bulk_update`, `--limit`, off-peak |

## 11. Open questions

- **`names` cap** — 10 enough? (vt_tool joins all with `", "`.) Proposing 10 +
  a `+N more` count.
- **GTI enrichment** — same extractor pattern would work for
  `GoogleThreatIntelligence_GetReport` (it returns a VT-superset JSON). Left out
  of this chunk deliberately; trivial follow-up if the SOC wants the GTI vendor
  breakdown too.
- **Backfill re-scoring** — this chunk backfills *display* enrichment only. Do
  we also want a one-off re-score of historical VT-analyzed cases under the
  refined rule? Proposing no — `backtest_scoring` shows the delta, and
  re-scoring closed cases churns TheHive/MISP. Revisit if the SOC asks.
