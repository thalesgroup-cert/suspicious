# IOC Analysis Road — Design

**Status:** Draft for review
**Date:** 2026-09-02
**Author:** Theo Bhang (Thales Group CERT)
**Related:** [`2026-09-02-scoring-verdict-model-design.md`](2026-09-02-scoring-verdict-model-design.md) · SOC roadmap feedback (Sept 2026)
**Council:** pressure-tested 2026-09-02 (5 advisors + peer review) — verdict: build the multi-IOC case model, deliver as small increments, keep the scoring-engine change off the critical path.

---

## 1. Problem

SOC analysts use Suspicious for two different jobs that currently share one pipeline:

1. **"Is this email phishing?"** — a classification question, answered by the AI Mail Analyzer plus supporting analyzers.
2. **"Is this indicator known-bad?"** — a reputation/enrichment question about a URL, IP, hash, or domain, answered by external CTI sources.

Today both produce one `Case` with one blended 0–10 score. Analyst feedback:

- The blended score is a black box ("éviter l'effet boîte noire").
- IOC analysis is missing the detail analysts need: which vendors flagged the indicator, ISP/geo, VT first/last-seen, hash↔filename, a page screenshot.
- No way to submit a list of indicators at once (bulk).
- The SOAR use case (submit via API, get a result into a ticket) is only half-supported.

This spec covers the **IOC road**: a dedicated submission path, data model, analysis page, bulk support, and API. The verdict model it uses is specified in the sibling doc.

### Non-goals

- Changing the mail-analysis verdict aggregation (sibling spec, and only a legibility pass there).
- A formal per-signal explainability data structure on the scoring engine (deferred, post-waiver).
- Cross-case IOC deduplication (a real SOC need, tracked separately — see §11).
- Multi-tenant / per-team scoring policies.

### Design goal: two isolated roads

The mail road and the IOC road are deliberately kept as **separate pipelines** — separate containers, separate verdict presentation, separate tests. Each is small enough to reason about and debug alone; a change to one cannot regress the other. This isolation is the point, not an accident of implementation.

---

## 2. Current architecture (what exists)

| Concern | Today |
|---|---|
| Mail submission | `SubmitFileView` — `.eml`/`.msg` routed to the mail pipeline; `Case.fileOrMail → CaseHasFileOrMail → Mail`. `Mail` has `mail_artifacts` (**N** embedded URLs/IPs/hashes/domains/addresses via `MailArtifact` + `ArtifactIs*` wrappers). |
| IOC submission | `SubmitUrlView` / `SubmitOtherView` — `Case.nonFileIocs → CaseHasNonFileIocs`, which holds **≤1** URL + ≤1 IP + ≤1 hash. |
| Artifact ledger | `CaseArtifact` — one row per (case, artifact), supports N per case. **Currently a passive audit record**, not read by scoring or dispatch. |
| Dispatch | `CaseHandler.dispatch_pending(case)` → per (instance, data_type) → `CortexJob.run_analyzer`. For generic IOC types it runs **every** Cortex analyzer registered for that type. Already per-artifact. |
| Analyzer→case mapping | `collect_case_targets(case)` walks `case.fileOrMail` / `case.nonFileIocs` and returns every `(instance, data_type)`. `build_analyzer_report_filter` turns that into the `AnalyzerReport` query. |
| Scoring | `collect_signals(case)` → list of `Signal` + AI signal + deny/allow flags → `score_case(...)` (pure function) → one `CaseVerdict` → `apply_verdict(case, verdict)` writes `Case.score/results/...`. |
| Per-IOC score | `IP` / `URL` / `Hash` / `Domain` models already carry persisted `ioc_score` / `ioc_confidence` / `ioc_level`, written per-artifact by `process_ioc` → `update_ioc_with_scores`. |
| Finalisation | webhook → `process_cortex_job(case_id, job_id)` on Celery → per-case Redis lock → `CaseAnalyzerJob` ledger update → `finalise_case` when all case jobs are non-pending. |
| KPI | `dashboard.models` `update_case_results(case.results)` — **already categorical** (Safe/Inconclusive/Suspicious/Dangerous/Failure). Does not read the numeric score. |
| Connectors | `case_finalised` event → registry fan-out → TheHive/MISP connectors receive the `Case`. |
| UI submit | `SubmitPage` — `mode: "file" | "artifact"`. The "artifact" mode already says *"Submit one artifact at a time."* |
| UI investigation | `InvestigationPage.tsx` (~1300 lines) already groups `analyzer_reports` by artifact with expand/collapse (`groupReportsByArtifact`). |

**Key insight:** a mail case is *already* a multi-artifact case internally. `score_case` already aggregates N signals → 1 verdict. The only thing that is genuinely single-valued is the `CaseHasNonFileIocs` container on the IOC road.

---

## 3. Data model

### 3.1 New: `ObservableGroup` + `ObservableGroupArtifact`

A container mirroring `Mail` — a thin envelope with a set of observables hanging off it.

```
ObservableGroup
  id
  label            CharField(blank=True)   # e.g. "SOAR alert #4823" — optional
  creation_date    auto_now_add
  last_update      auto_now

ObservableGroupArtifact
  id
  group            FK(ObservableGroup, related_name="artifacts", on_delete=CASCADE)
  artifact_type    CharField(choices=URL/IP/HASH/DOMAIN, db_index=True)
  url              FK(URL,    null=True, blank=True)
  ip               FK(IP,     null=True, blank=True)
  hash             FK(Hash,   null=True, blank=True)
  domain           FK(Domain, null=True, blank=True)
  creation_date    auto_now_add
```

- Exactly one of `url`/`ip`/`hash`/`domain` is populated per row; `artifact_type` matches.
- **Leaner than `MailArtifact`**: no `ArtifactIs*` indirection layer (that layer exists to carry `times_sent` per mail-artifact; the IOC road does not need it initially).
- **No per-group score fields.** The observable's own `ioc_score` / `ioc_confidence` / `ioc_level` is the per-IOC verdict.
  `# ponytail: no per-(group, artifact) score. The IOC model's own ioc_* fields are the verdict.`
  `# Upgrade path: add score fields here if the same IOC must score differently in different groups (mail needs this; pure reputation lookup does not).`

### 3.2 `Case` wiring

Add a new nullable FK; **do not** repoint `nonFileIocs`.

```
Case.observable_group = FK(ObservableGroup, null=True, blank=True,
                           related_name="cases", on_delete=CASCADE, db_index=True)
```

- New IOC-road cases set `observable_group`, leave `nonFileIocs` null.
- Legacy single-IOC cases keep `nonFileIocs`, `observable_group` null — **zero data migration**, they keep working unchanged.
- `# ponytail: two IOC containers coexist during transition. Read-time branch in collect_case_targets only — not an engine fork.`
- **Later** (own ticket, post-waiver): backfill each `CaseHasNonFileIocs` into a 1-artifact `ObservableGroup`, drop `nonFileIocs`.

### 3.3 Migrations

1. Create `ObservableGroup`, `ObservableGroupArtifact`, `Case.observable_group`. Additive, no data change.
2. (Deferred) Backfill + remove `nonFileIocs`.

---

## 4. Submission flow

### 4.1 Two roads, made explicit in the UI

`SubmitPage` keeps `mode`, relabelled:

| Mode | Accepts | Pipeline |
|---|---|---|
| **Email** (`file`, `.eml`/`.msg`) | one email file | mail pipeline (unchanged) |
| **File** (`file`, other) | one file sample | file pipeline (unchanged) |
| **Indicators** (`ioc`) | **one or many** IOCs, free text | IOC road (new) |

The "Indicators" panel:
- A textarea. Split input on newline / comma / whitespace. Trim, dedupe (case-insensitive for domains/URLs).
- Per line: detect type by reusing Suspicious's existing classifiers — `IPHandler().validate_ip`, `HashHandler().validate_hash`, plus the URL/domain validators used in `CaseHandler._handle_other_form` / `SubmitUrlSerializer`. Defang-aware (`hxxp`, `[.]`).
- Preview list: `value → detected type`, with unparseable lines flagged and excluded.
- Optional shared `context` field.
- Submit.

### 4.2 Backend

New `SubmitIndicatorsView` (`POST /api/submit/indicators/`), `IsAuthenticated`, Knox token or session.

```
1. Validate + classify each indicator (serializer). Reject if zero valid.
2. get_or_create the URL/IP/Hash/Domain rows (existing per-type helpers).
3. Create ONE Case (CaseCreator), attach a new ObservableGroup with N ObservableGroupArtifact rows.
   Also write CaseArtifact rows (keep the audit ledger complete).
4. Allow-list check per observable (see §7). Fully allow-listed group → Case finalised AllowListed, no dispatch.
5. handler.dispatch_pending(case) — loops group.artifacts, one Cortex job set per observable.
6. Return {case_id, observable_count, accepted_count, skipped: [...]}.
```

`SubmitUrlView` / `SubmitOtherView` stay as-is (single-indicator convenience, still create `nonFileIocs` cases) **or** become thin wrappers that build a 1-element `ObservableGroup`. Decision: **keep them unchanged** for now to minimise surface; revisit at backfill time.

### 4.3 CaseCreator changes

`CaseCreator.create_case` gains an `observable_group_instance` kwarg handled like `mail_instance`: attach, set `case.observable_group`, write `CaseArtifact` rows for each observable.

---

## 5. Analyzer dispatch

`collect_case_targets(case)` gains a branch, structurally identical to the existing `mail.mail_artifacts` walk:

```python
group = getattr(case, "observable_group", None)
if case.observable_group_id and group:
    for a in group.artifacts.select_related("url", "ip", "hash", "domain"):
        obj = a.url or a.ip or a.hash or a.domain
        if obj:
            _add(obj, a.artifact_type.lower())
```

Everything downstream (`build_analyzer_report_filter`, `dispatch_pending`, the webhook, `CaseAnalyzerJob`, `finalise_case`, `fail_stale_jobs`) is already per-artifact and **needs no change** — it operates on `(instance, data_type)` targets and per-case job ledgers.

---

## 6. Scoring / verdict (summary — full detail in sibling spec)

- `collect_signals(case)` gains an `ObservableGroup` branch: `for a in group.artifacts: process_ioc(obj, type, ...)` → append `Signal`s. Same shape as the mail-artifact loop.
- The **IOC-road case verdict** is produced by the new categorical engine (sibling spec): a trust-weighted vote of per-source categorical verdicts → `Safe / Suspicious / Dangerous / Inconclusive` + an aggregate confidence + the evidence list. **No 0–10 score is shown.**
- `Case.score` / `final_score` are still written (derived band number: Safe≈2 / Suspicious≈6 / Dangerous≈9) purely so dashboard sort, KPI history, and TheHive severity keep working. Never displayed on the IOC road.
- Per-IOC verdict in the UI = each observable's own `ioc_level` / `ioc_confidence`, already persisted.
- `backtest_scoring` byte-identical requirement applies to the **mail path only** — the IOC road is greenfield and has no prior verdicts to drift from.

---

## 7. Allow / deny lists

- **New:** `AllowListIp` model + an `ip` branch in `check_allow_list` (currently file/filetype/domain/url only). This fixes the `8.8.8.8` false positive and any known-infrastructure IP.
- Deny-list logic (`_compute_deny_listed`) already walks mail artifacts; add an `ObservableGroup` branch so a deny-listed observable in a group forces that observable — and by rule the group band — to Dangerous.
- Allow-listed observable → that observable is cleared; a fully allow-listed group short-circuits to `AllowListed`.

---

## 8. The IOC analysis page

### 8.1 In-app view (simple)

Route: the existing investigation detail route renders an **IOC-group layout** when `case.observable_group` is set.

- **Header:** categorical verdict badge + confidence + the ratio — `3 / 9 trusted sources flagged this`.
- **Count strip:** `12 observables · 2 dangerous · 3 suspicious · 6 clean · 1 no-data`.
- **Per-observable rows** (reuse/extend `groupReportsByArtifact`): value, own verdict badge, type icon, one-line "why" (top source + finding). Expand → the per-source table:

  ```
  GTI           🔴 malicious    C2 infrastructure
  VirusTotal    🟢 clean        0 / 72 engines           [drill down]
  MISP          🔴 malicious    event #4821
  AbuseIPDB     🟠 suspicious   confidence 42%
  Shodan        ⚪ enrichment   open ports 22, 443
  urlscan       🟢 clean        screenshot ▸
  ```

- **Per-observable:** "copy result" button (plain-text summary for pasting into a ticket).
- **Case-level:** "Full report" button (§8.3).

Component reuse: start from VT Tool's `AnalysisDetailPage` component structure, restyled to Suspicious's MUI design system. The per-source table component is **shared** with the mail page (sibling spec §3 — embedded-IOC panels).

### 8.2 API

- `GET /api/investigations/<case_id>/` — extend the serializer, on the IOC road, to include:
  - `observable_group`: `[{value, type, verdict, confidence, sources: [{name, tier, verdict, evidence, ...}]}]`
  - `report_full` per analyzer report (currently omitted — only `report_summary` + `report_taxonomy` are exposed). This is where VT vendors/dates/geo/filenames live.

### 8.3 Full report (downloadable)

New endpoint `GET /api/cases/<case_id>/report/?format=html|pdf`.

- Server-renders a templated document — styled like the council report artifacts (clean briefing-document layout, theme-neutral).
- Contents: case metadata, verdict + rationale, per-observable section with every source's full detail (`report_full` payloads formatted), timestamps, analyzer versions.
- `html` served inline / saved by the browser; `pdf` via a server-side renderer (WeasyPrint or wkhtmltopdf — pick at implementation, WeasyPrint preferred: pure-Python, no headless browser).
- Sits beside the existing `GET /api/cases/<case_id>/download/` (case archive). Different artifact: archive = raw files, report = formatted analysis.
- `# ponytail: one template, two output formats. No per-section config, no report builder UI.`

---

## 9. Bulk concerns

| Concern | Resolution |
|---|---|
| Reporter email | One `Case` = one notification. Already per-case — nothing to suppress. |
| KPI | One `Case` = one row, counted as its rollup band via `case.results` (already categorical). `# ponytail: revisit only if dashboards need per-IOC counts.` |
| ChromaDB similarity | Runs per-case on the mail-analysis context. On the IOC road: **skip it** initially (it is a phishing-campaign feature). `# ponytail: add per-observable similarity later if asked.` |
| Finalisation | One per-case Redis lock, `finalise_case` when all group jobs settle. Works unchanged. A large group blocks on its slowest analyzer; `fail_stale_jobs` (24h) covers hangs. |
| Group size | Cap at `IOC_GROUP_MAX` (default 100) in the serializer. Larger → 400 with a clear message. `# ponytail: raise the cap when someone hits it, don't build pagination now.` |
| Dispatch load | N observables × M analyzers Cortex jobs from one submission. Existing per-case job ledger and Cortex's own queue absorb this; monitor and add a per-submission rate-limit only if it bites. |

---

## 10. Connectors (TheHive / MISP)

- The connector already receives a finalised `Case`. Add: enumerate `collect_case_targets(case)` → build one observable per target → **one alert with N observables**.
- `build_mail_observables_from_*` helpers get an IOC-group sibling (`build_group_observables`).
- Severity mapped from `case.results` (categorical), not the numeric score.
- `# ponytail: one alert per case. Add a per-observable fan-out mode only if SOC asks for one ticket per IOC.`

---

## 11. Out of scope / follow-ups

- **Cross-case IOC dedup** — "this hash was seen in 4 previous cases." Real SOC value, needs its own design (a sightings index keyed by observable). Not this spec.
- **VT Tool absorption** — this road overlaps VT Tool's purpose. Migration/consolidation is a separate decision once the IOC road is proven.
- `nonFileIocs` removal + backfill.
- Per-observable similarity search.

---

## 12. Testing

| Area | Tests |
|---|---|
| Model | `ObservableGroup` / `ObservableGroupArtifact` creation; `Case.observable_group` FK; exactly-one-FK-populated constraint. |
| Submission | multi-line parsing (newline/comma/space, defanged, dupes, junk lines); type detection per indicator; `SubmitIndicatorsView` creates one `Case` + `ObservableGroup` + N artifacts + N `CaseArtifact`; zero-valid → 400; group size cap. |
| Dispatch | `collect_case_targets` returns every group observable exactly once (dedup by `(type, pk)`); `dispatch_pending` fires per observable; legacy `nonFileIocs` cases still resolve targets. |
| Scoring wiring | `collect_signals` emits one signal set per observable; a group case reaches a categorical verdict; `apply_verdict` writes a derived `Case.score`. |
| Allow/deny | `AllowListIp` clears an IP observable; fully allow-listed group → `AllowListed`, no dispatch; deny-listed observable → group Dangerous. |
| API | investigation detail includes `observable_group` + `report_full` on the IOC road and **omits** them on mail/file cases (isolation check); `/report/` renders HTML for a finalised group case. |
| Regression | `python manage.py backtest_scoring` — verdict bands unchanged for all existing (mail + legacy-IOC) cases. |
| Frontend | Indicators submit panel (parse preview, junk-line handling); IOC-group investigation layout renders ratio + per-source table; "copy result" produces the expected text; mail-case layout unchanged. |

---

## 13. Sequencing

1. **Spike (1 day):** `ObservableGroup` prototype, wire 3–5 IOCs into one `Case` via the new container, run `backtest_scoring`, confirm mail + legacy-IOC verdicts byte-identical.
2. **Model + migration + `CaseCreator` + `collect_case_targets` branch.** Single indicator through the new container behind a feature check.
3. **`SubmitIndicatorsView` + serializer + multi-line UI.** Bulk works end to end, current verdict presentation.
4. **`AllowListIp` + deny/allow group branches.**
5. **IOC-group investigation layout** + expose `report_full` + port VT Tool's VirusTotal field parsing into `contrib/virustotal.py` (see SOC roadmap, "S'appuyer sur VT Tool").
6. **Full-report endpoint + template.**
7. **Connector one-alert-N-observables.**
8. CTI connectors (Shodan, AbuseIPDB, urlscan, GTI) — independent, parallel from step 1.

Steps 1–4 are shippable and close "bulk" + the `8.8.8.8` class of false positive. The verdict-model spec runs alongside and lands at step 5.
