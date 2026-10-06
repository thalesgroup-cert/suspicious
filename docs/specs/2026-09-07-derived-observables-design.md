# Derived observables — analyzing what an extractor analyzer surfaces

**Date:** 2026-09-07
**Status:** design, approved for planning
**Context:** Phase B of the "decoded URLs never get analyzed" thread
(`docs/specs/2026-09-07-analyzer-taxonomy-audit.md` §"Not touched" #1). Phase A
(`3c024f95`) unwrapped SafeLinks / URLDefense at submission time. Phase B covers
the extractors that need a runtime: **UnshortenLink** (follows HTTP redirects to
the real destination) and **QrDecode** (decodes URLs/indicators out of a QR
image — the "quishing" vector).

## Goal

When an *extractor* analyzer finishes and its report contains a new indicator
(the unshortened URL, the URL inside a QR code), that indicator becomes a real
observable in the same case: it gets its own analyzer coverage and its own
verdict, and if it scores Suspicious/Dangerous it **escalates its parent
observable** (the short link / the QR image file) and records why.

## Non-goals

- **1 hop only.** A derived observable is analyzed but never itself re-extracted.
- No new Cortex analyzers. UnshortenLink and QrDecode are already enabled
  (`deployment/scripts/enable-dev-analyzers.sh`).
- `auto_extract_artifacts` stays `false` — we parse specific fields of
  `report_full`, not Cortex's generic regex-over-the-whole-report extraction.
- No lifecycle re-opening. Derived jobs are injected *before* a case finalizes.
- Not a general "ingest every analyzer's `artifacts[]`" mechanism — a small,
  explicit per-analyzer registry (easy to extend later).

## Background — the current pipeline

1. `dispatch_case_analysis` (`tasp/tasks.py`) resolves the case's observables
   via `collect_case_targets` and calls `CortexJob().launch_cortex_jobs(value,
   data_type, case)` per target, which creates `CaseAnalyzerJob` ledger rows.
2. Cortex POSTs `/api/cortex/webhook/` per finished job → `process_cortex_job`
   → per-case Redis lock → `reconcile_case` → `reconcile_case_core`
   (`cortex_job/cortex_utils/reconciliation.py`).
3. `reconcile_case_core`: sync every pending `CaseAnalyzerJob` from Cortex; if
   **any** still pending → stay `ANALYZING`, return. Else → `SCORING` →
   `finalise` → `FINALIZED` → `emit_connector_event("case_finalised")`.
4. `finalise` → `CortexAnalyzerReports.get_report(case)`:
   - IOC-group case → `finalise_ioc_group` (`score_process/scoring/apply.py`):
     per observable `score_observable(sources)` → writes `obj.ioc_level/…`;
     `score_group` → case band + `case.verdict_rationale`.
   - mail case → `collect_signals` → flat `Signal` list → `score_case`
     (`score_process/scoring/engine.py`) → one case verdict.
5. Celery beat `update_ongoing_cases` re-runs `reconcile_case` every 300s as a
   webhook-loss fallback; `fail_stale_jobs` fails `CaseAnalyzerJob`s pending
   > `STALE_JOB_TIMEOUT_SECONDS`.

Nothing today reads an analyzer report's extracted indicators.
`mail_band_escalation` exists in `engine.py` but is **not wired to any caller** —
Phase B wires it.

## Design

### 1. Extractor registry — `cortex_job/cortex_utils/derived_observables.py`

```python
# cortex analyzer name -> (report_full: dict) -> list[(value: str, data_type: str)]
EXTRACTORS: dict[str, Callable[[dict], list[tuple[str, str]]]] = {
    "UnshortenLink_1_2": _unshorten,
    "QrDecode_1_0": _qrdecode,
}
```

- `_unshorten(full)` → `[(full["url"], "url")]` when `full.get("found")` and
  `full.get("url")`; else `[]`.
- `_qrdecode(full)` → for each `r` in `full.get("results_list", [])`, take
  `r["results"]["data"]` + `r["results"]["data_type"]`; keep only
  `data_type ∈ {url, domain, ip, hash, mail}` (the analyzer already classifies).

Each function is pure, guards its own shape access, returns `[]` on anything
unexpected. Adding EmlParser sub-artifacts later = one dict entry + one function.

The registry is keyed by the exact Cortex analyzer name; matching is against
`AnalyzerReport.analyzer.name` and `analyzer.analyzer_cortex_id` (same dual key
the parser registry uses).

### 2. Provenance model — `cortex_job/models.py`

```python
class DerivedObservable(models.Model):
    case          = FK(Case, on_delete=CASCADE, related_name="derived_observables")
    source_report = FK(AnalyzerReport, on_delete=CASCADE)
    via_analyzer  = CharField(max_length=64)          # "QrDecode_1_0"

    parent_type   = CharField(max_length=16)          # url|domain|ip|hash|file
    parent_id     = PositiveIntegerField()
    child_type    = CharField(max_length=16)          # url|domain|ip|hash|mail
    child_id      = PositiveIntegerField()
    child_value   = CharField(max_length=512)         # denormalized for note + UI

    child_band      = CharField(max_length=16, blank=True, default="")   # set at scoring
    escalation_note = CharField(max_length=255, blank=True, default="")
    created_at      = DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            UniqueConstraint(fields=["source_report", "child_type", "child_id"],
                             name="uniq_derived_per_report_child"),
        ]
```

`(type, id)` pointers rather than typed FKs — matches the lightweight, mostly
never-deleted, globally-shared observable rows; cascade from `case` /
`source_report` covers cleanup; scoring/UI lookups tolerate a missing target.
The unique constraint is the idempotency guard.

### 3. Ingestion — `ingest_derived_observables(case) -> int`

New function in `derived_observables.py`. Returns the number of new
`CaseAnalyzerJob`s dispatched.

```
if not get_config("derived_observables.enabled", True): return 0

derived_child_keys = {(d.child_type, d.child_id) for d in case.derived_observables.all()}
new_jobs = 0
for report in _finished_extractor_reports(case):
    if report already has a DerivedObservable (unique key): continue
    parent = the observable the report was filed against (from report's FK columns)
    if (parent_type, parent.pk) in derived_child_keys: continue      # 1-hop cap
    for (value, data_type) in EXTRACTORS[report.analyzer_name](report.report_full):
        if _blocked(value, data_type):  continue                     # SSRF + allow-list
        obj = get_or_create observable model for (value, data_type)
        _attach_to_case(case, obj, data_type)                        # MailArtifact | ObservableGroupArtifact
        DerivedObservable.objects.create(case=…, source_report=report,
            via_analyzer=report.analyzer_name, parent_type=…, parent_id=parent.pk,
            child_type=data_type, child_id=obj.pk, child_value=value)
        new_jobs += len(CortexJob().launch_cortex_jobs(value=obj, data_type=data_type, case=case))
return new_jobs
```

- `_finished_extractor_reports(case)` — `AnalyzerReport`s for this case's
  observables whose `analyzer.name ∈ EXTRACTORS` and `status == "Success"`.
  Reuses `collect_case_targets` + `build_analyzer_report_filter` to scope to the
  case.
- `_blocked(value, data_type)` — for `url`, run `_check_no_ssrf_ip`
  (`api/serializers/submit.py`); for `url`/`domain`, run the domain allow-list
  check (`check_allow_list`). A QR encoding `http://169.254.169.254/` must not
  become a live observable.
- `_attach_to_case`:
  - IOC-group case → `ObservableGroupArtifact.objects.get_or_create(group=…,
    artifact_type=…, <fk>=obj)`
  - mail case → `MailArtifact` + the `ArtifactIsUrl`/`ArtifactIsX` join row
    (same shape `mail_feeder/utils/process_artifacts/artifacts.py::_process_url`
    builds).
- `launch_cortex_jobs` already dedups against Cortex's `cacheTag` window and
  writes `CaseAnalyzerJob` rows.

### 4. Wiring into the loop — `reconcile_case_core`

```python
    if still_pending:
        ...transition ANALYZING; return

    # NEW: pull in anything the finished extractors surfaced. If this
    # dispatches jobs, the case is not done — the next reconcile pass
    # (webhook or the 300s poll) handles them.
    if ingest_derived_observables(case) > 0:
        return

    if case.dispatched_at is None and <grace>: return
    ...SCORING → finalise → FINALIZED
```

Idempotent: the `DerivedObservable` unique key means a second pass over the same
extractor report is a no-op, and a derived observable already attached is a
`get_or_create` hit. Termination: the 1-hop check means a derived observable's
own (non-extractor) reports never feed another ingest, and an extractor run on a
derived observable is skipped.

### 5. Scoring — escalate parent + note

One shared helper, `score_derived_observables(case)`, run by both roads after
their per-observable pass:

```
for d in case.derived_observables.select_related("source_report"):
    child_sources = source verdicts from the child's finished reports
    child_v = score_observable(child_sources)
    d.child_band = child_v.band
    if child_v.band in {"Suspicious", "Dangerous"} and _band_rank(child_v.band) > _parent_band_rank(d):
        d.escalation_note = f"Escalated to {child_v.band}: {d.via_analyzer} extracted {d.child_value} → {child_v.band}."
        yield (d.parent_type, d.parent_id, child_v.band, d.escalation_note)
    d.save(update_fields=["child_band", "escalation_note"])
```

`_parent_band_rank(d)` reads the parent's current band: the parent's
`ObservableVerdict.band` on the IOC road, or `MailArtifact.artifact_level`
(mapped through `_BAND_TO_IOC_LEVEL`, default `info`) on the mail road.

**IOC road** (`finalise_ioc_group`): after the `obs_verdicts` loop, before
`score_group` — for each yielded parent, find its `ObservableVerdict`, raise its
band, append `escalation_note` to that verdict's rationale (so `score_group`
picks up the escalation and it lands in `case.verdict_rationale`). Also bump the
parent `URL`/`Domain` row's `ioc_level`/`ioc_score` the same way the loop does.

**Mail road** (`CortexAnalyzerReports.get_report`, mail branch): after
`score_case`, call the now-wired `mail_band_escalation(verdict, embedded)` where
`embedded` = the derived observables' `ObservableVerdict`s. Set the parent
`MailArtifact.artifact_level` to the child band for each escalated parent
(mail's first real per-artifact level write outside the deny-list path). The
"Band raised by an embedded indicator" rationale line already exists in
`mail_band_escalation`; extend it to name the analyzer + extracted value.

The derived observable's *own* analyzer reports flow into the case verdict
automatically on both roads (IOC: new `ObservableGroupArtifact` seen by
`collect_observable_sources`; mail: new `MailArtifact` reports seen by
`collect_signals`) — so a quishing mail is flagged even if the escalation
wiring is disabled.

### 6. API + frontend

- **IOC detail** (`api/utils/observable_report.py::assemble_observables`): add
  per observable `derived_from: {value, via_analyzer} | null` and
  `escalation_note: str`.
- **`ObservableGroupPanel.tsx`**: on a child observable show a small
  "⛓ extracted from `<parent>` via `<analyzer>`" chip; on an escalated parent
  show the `escalation_note`.
- **Mail detail** (investigations serializer): expose the same two fields on the
  artifact list; render the note.
  > **Deferred (2026-09-08):** the initial cut ships the mail road as
  > **scoring/escalation logic only** — `mail_band_escalation` runs, the parent
  > `MailArtifact.artifact_level` is bumped, and the escalation line lands in
  > `case.verdict_rationale`, so an analyst sees *why* a quishing mail escalated.
  > The per-artifact "extracted from … via …" chip + structured `escalation_note`
  > on the mail detail page (`api/serializers/investigations.py` + mail UI) is a
  > tracked follow-up.

### 7. Config

- `derived_observables.enabled` (bool, default `true`) — checked at the top of
  `ingest_derived_observables`. Kill switch, added to `settings/config.py`
  defaults + `seed_config`.
- `auto_extract_artifacts` — unchanged (`false`).

## Data-flow walkthrough

Bulk-IOC submission of `https://tinyurl.com/xxxx`:

1. `dispatch_case_analysis` → UnshortenLink + the URL type-dispatch pool run on
   the tinyurl. `CaseAnalyzerJob`s created.
2. Webhook per job → `reconcile_case_core`. While the URL pool is still running,
   `still_pending` → stay `ANALYZING`.
3. All the tinyurl's jobs finish. `still_pending` false →
   `ingest_derived_observables`:
   - UnshortenLink report `full = {"found": true, "url": "https://evil.example/login"}`
   - not SSRF, not allow-listed → `URL.objects.get_or_create(address=…)`
   - new `ObservableGroupArtifact` on the case's group
   - `DerivedObservable(parent=url:tinyurl, child=url:evil.example, via=UnshortenLink_1_2)`
   - `launch_cortex_jobs` → N new `CaseAnalyzerJob`s → returns N > 0 → reconcile
     returns, case stays `ANALYZING`.
4. `evil.example` jobs finish → next reconcile pass: `ingest` finds the
   UnshortenLink report already has a `DerivedObservable` (skip) and
   `evil.example` is a derived child so its own reports are 1-hop-capped →
   returns 0 → `SCORING`.
5. `finalise_ioc_group`: `evil.example` scores Dangerous. Post-pass raises the
   `tinyurl` observable to Dangerous, note "Escalated to Dangerous:
   UnshortenLink_1_2 extracted https://evil.example/login → Dangerous."
   `score_group` → case Dangerous.

## Edge cases

- **Extractor is the only analyzer and finds nothing** → `EXTRACTORS[...]`
  returns `[]`, no `DerivedObservable`, `ingest` returns 0, normal finalize.
- **Derived observable equals an existing case observable** (QR encodes a URL
  already submitted) → `get_or_create` hit + `ObservableGroupArtifact`
  `get_or_create` hit; `DerivedObservable` still recorded (provenance), no
  duplicate jobs (Cortex `cacheTag` dedup + planner collapse).
- **Redo-analysis** (`FINALIZED → ANALYZING`): existing `DerivedObservable` rows
  stay; their children are already case observables and get re-dispatched
  normally; `ingest` re-runs but the unique key prevents dup rows.
- **Extractor job fails** → not `Success`, skipped by
  `_finished_extractor_reports`.
- **SSRF / allow-listed derived value** → dropped in `_blocked`, no observable,
  logged. (No `DerivedObservable` row — nothing to show.)
- **Stale-job / webhook loss** → the 300s `update_ongoing_cases` poll drives the
  same `reconcile_case_core`, so ingestion still happens, just later.
- **QR with many codes** → each becomes an observable; rely on the IOC group cap
  / URL planner per-domain cap already in `dispatch_case_analysis`.

## Testing

- `derived_observables.py` unit: `_unshorten` / `_qrdecode` shape handling
  (found/not-found, empty `results_list`, non-url data types, garbage `full`).
- `ingest_derived_observables`: creates observable + `ObservableGroupArtifact` +
  `DerivedObservable` + dispatches (mock `launch_cortex_jobs`); idempotent on
  second call; 1-hop cap (no ingest from a derived child's reports); SSRF drop;
  `derived_observables.enabled=false` → no-op.
- `reconcile_case_core`: a case with an unprocessed extractor report stays
  `ANALYZING` after a pass that dispatches derived jobs; finalizes once the
  derived jobs complete and the next pass ingests nothing.
- Scoring: IOC-road parent escalation + rationale line; mail-road
  `mail_band_escalation` wired + `MailArtifact.artifact_level` bumped; child's
  own reports move the case verdict with escalation disabled.
- Serializer: `derived_from` / `escalation_note` present.
- Frontend: `ObservableGroupPanel` renders the chip + note (vitest).

## Rollout

- Migration: `DerivedObservable` + config default.
- `derived_observables.enabled` defaults true; flip to false in `settings.json`
  to disable without a deploy.
- Live-verify on the dev e2e stack: submit a known shortener and a mail with a
  QR-code image attachment; confirm the derived observable appears, is analyzed,
  and escalates.
