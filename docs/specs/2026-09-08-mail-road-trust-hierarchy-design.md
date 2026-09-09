# Mail-road trust hierarchy — converge on the categorical engine

**Date:** 2026-09-08
**Status:** design, approved for planning
**Context:** SOC roadmap Lot 1 (blocks the dérogation) — "trusted-source hierarchy
in the engine". The IOC road got the trust-weighted categorical engine
(`score_process/scoring/observable_engine.py`, commit `ef5e9aa9`); the mail road
never did. On the mail road a Tier-1 GTI/VT verdict has no more structural pull
than a Tier-3 OSINT one, and a single Tier-3 "suspicious" URL (e.g.
`Urlscan_io_Search`, which flags every URL with a prior scan) can drag a whole
mail case toward Dangerous.

## Goal

A mail case's **embedded observables** (the URLs / IPs / domains / hashes /
mail-addresses lifted from the message) are scored by the same trust-weighted
`score_observable` engine the IOC road uses, then merged into the mail verdict
via the already-wired `mail_band_escalation`. The mail-*intrinsic* analyzers
(AI phishing classifier, YARA-on-body, sandbox, header analysis, FileInfo on
attachments) keep their existing weighted `score_case` path.

Net effect:
- Tier-1 authoritative verdicts (GTI/VT/MISP) on an embedded IOC drive the mail
  band; Tier-3 OSINT noise is capped at Suspicious per the categorical rules.
- Each embedded observable's `ObservableVerdict.rationale` ("GTI (authoritative)
  reports the URL malicious") flows into `case.verdict_rationale` — this also
  advances Lot 1's "verdict explanation" item.
- Per-`MailArtifact` levels get written for the first time outside the deny-list
  path — feeds the mail-detail UI and the ticket endpoint (SOC roadmap item #3).

## Non-goals

- No change to the IOC-group road (`finalise_ioc_group`) — it already does this.
- No change to `score_observable` / `mail_band_escalation` **rules**; only new
  call sites and (if strictly needed) a confidence-merge tweak.
- Not touching the AI / YARA / sandbox / header scoring — those stay on
  `score_case`.
- No new Cortex analyzers, no schema change to `AnalyzerReport`.
- The fallback (a plain Tier multiplier in `compute_weighted_scores`) is **not**
  the endpoint — it is only the escape hatch if this design regresses the
  labelled accuracy harness (see Rollout).

## Background — the mail road today

`CortexAnalyzerReports.get_report(case)` → mail branch:

1. `manage_ai_jobs(case)` (AI classification, supplementary).
2. `signals, ai, deny_listed, ai_missing, deny_reason = collect_signals(case)`
   - `collect_signals` → `process_mail(mail, …)` which walks **every** part:
     `mail_body`, `mail_header`, `mail_archive`, each `mail_attachment`, **and
     each `mail_artifact`** (the embedded URL/IP/domain/hash/mailaddress).
   - Each part → `compute_weighted_scores(reports)` =
     `Σ(score·analyzer.weight) / Σ(weight)` → a `(score, confidence)` pair
     appended to flat lists → `Signal(source=<coarse type>, score, confidence,
     is_malicious=score≥8, is_failure=False)`. **Analyzer identity and tier are
     gone by this point.**
3. `verdict = score_case(signals, ai, deny_listed, ai_missing, deny_reason)` —
   worst high-confidence score vs. weighted mean, AI override, malicious-vote
   count (`n_malicious ≥ max(1, n_scored // 3)` → Dangerous).
4. Phase B: `verdict = _apply_derived_escalation(case, mail, verdict)` — the
   *derived* observables (Phase B) already route through `score_observable` +
   `mail_band_escalation`. This design generalizes that to **all** embedded
   observables.
5. `apply_verdict(case, verdict)`.

`compute_weighted_scores` *does* apply `analyzer.weight` — but weight is a flat
per-analyzer float (default 0.2, hand-editable via `/api/settings/analyzers/`),
not the structured Tier logic (`TIER_MULTIPLIER = {1: 4, 2: 2, 3: 1}` plus the
"Tier-1 authoritative → Dangerous", "Tier-1 clean beats Tier-3 noise → Safe",
"Tier-3-only caps at Suspicious" rules) that `score_observable` encodes.

## Design

### 1. The split

| Bucket | Members | Scored by |
|---|---|---|
| **Mail-intrinsic** | `mail_body`, `mail_header`, `mail_archive`, `mail_attachments` (File) | `score_case` (unchanged) |
| **Embedded observables** | `mail_artifacts` → URL / IP / Domain / Hash / MailAddress | `score_observable` per observable |
| **Merge** | — | `mail_band_escalation(verdict, embedded_verdicts)` raises the mail band to the worst embedded band |

> **Implementation check:** confirm whether an attachment's file-hash is also
> recorded as a `mail_artifact` of type `Hash`. If it is, it correctly gets
> Tier-weighted treatment as an embedded observable while the attachment *file*
> stays intrinsic — no conflict, they are different `AnalyzerReport` rows
> (`hash=` vs `file=`). If it is not, no action.

### 2. Shared report-bucketing — extract the core of `observable_reports`

`observable_collect.py::observable_reports` already does "one `AnalyzerReport`
query for a set of observables, bucketed in Python by FK id, newest first,
folding `analyzed_url` representatives". Only its **input walk** is
IOC-group-specific (`case.observable_group.artifacts`).

Refactor: extract `_bucket_reports(triples)` where `triples = [(key, obj,
field), …]` (`key` = the stable identity to bucket under, `field` ∈
`{url,ip,hash,domain,mail}`). `observable_reports(case)` becomes a thin caller
that builds triples from `case.observable_group.artifacts`.

New sibling: **`mail_observable_reports(mail)`** — builds triples from
`mail.mail_artifacts` (two-hop: `artifact.artifactIsUrl.url`, etc.; skip
`MailAddress`-only artifacts that carry no analyzer reports if that proves
true), then calls `_bucket_reports`. Returns `[(mail_artifact, obj, field,
[reports])]`.

`_FIELD` gains `"MAILADDRESS": "mail"` (or the mail-artifact walk maps its
casing).

### 3. `collect_signals` — drop the embedded-artifact path for mail cases

In `process_mail` (`processing.py`), the `mail_artifacts` loop currently calls
`process_mail_artifact` → `process_ioc` → appends to `total_scores` /
`total_confidences`. For a mail **case** those scores must no longer feed
`score_case`.

Options (decide in the plan):
- **3a** — `process_mail(…, include_artifacts=False)` param; `collect_signals`
  passes `False`. `process_mail_artifact` still runs elsewhere? No — nothing
  else calls it. So the loop is simply skipped for scoring. But
  `process_mail_artifact` also does `artifact_obj.times_sent += 1` and persists
  `ioc.ioc_score` — side effects some views may read. Preserve those by having
  the new categorical path write them instead (see §5).
- **3b** — keep `process_mail_artifact` running for its side effects but have
  `collect_signals` **not** turn its appended scores into `Signal`s (track an
  offset, like it already does per-part). Lower blast radius. Preferred.

### 4. `get_report` mail branch

```python
signals, ai, deny_listed, ai_missing, deny_reason = collect_signals(case)
verdict = score_case(signals, ai, deny_listed, ai_missing, deny_reason)

if mail:
    verdict = CortexAnalyzerReports._apply_embedded_escalation(case, mail, verdict)

apply_verdict(case, verdict)
```

`_apply_embedded_escalation` **replaces** the Phase B `_apply_derived_escalation`:

```python
from score_process.scoring.observable_collect import mail_observable_reports
from score_process.scoring.observable_engine import score_observable
from score_process.scoring.sources import source_verdict_from_report
from score_process.scoring.engine import mail_band_escalation

embedded = []           # list[ObservableVerdict]
for m_art, obj, field, reports in mail_observable_reports(mail):
    seen, svs = set(), []
    for r in reports:
        if r.analyzer_id in seen:
            continue
        seen.add(r.analyzer_id)
        svs.append(source_verdict_from_report(r))
    if not svs:
        continue
    v = score_observable(svs)
    embedded.append(v)
    _write_mail_artifact_level(m_art, v)          # §5

if not embedded:
    return verdict

worst = max(embedded, key=lambda v: _BAND_ORDER[v.band])
rationale_lines = [l for v in embedded for l in v.rationale]
return mail_band_escalation(verdict, embedded, note="; ".join(rationale_lines[:5]) or None)
```

The Phase B derived-observable rows are now a strict subset — a derived
observable is a `MailArtifact` (Phase B `_attach_to_case` created it), so
`mail_observable_reports` picks it up. `DerivedObservable.child_band` /
`escalation_note` are still written by `score_derived_observables` for the
provenance UI; the *band merge* now comes from this unified path. Keep
`score_derived_observables(case)` being called (for `child_band` / the chip),
just stop using its return value for the mail-band merge.

### 5. Per-`MailArtifact` level writes

Shipped behaviour (a deliberate departure from this section's original "write
score/confidence unconditionally"): the **whole** write block — level *and*
score *and* confidence — is guarded on `_STICKY_IOC_LEVELS`, for BOTH the global
observable row (`obj.ioc_*`) and the per-`MailArtifact` row (`m_art.artifact_*`):

- If the current level is in `_STICKY_IOC_LEVELS` (`critical`,
  `SAFE-ALLOW_LISTED`) → skip the row entirely; a deny/allow-list marker owns
  the score and confidence too, not just the level string.
- Otherwise write `artifact_level` = `_BAND_TO_IOC_LEVEL[v.band]` (`Safe→safe`,
  `Suspicious→suspicious`, `Dangerous→malicious`, `Inconclusive→info`),
  `artifact_score` = `_DERIVED_SCORE[v.band]`, `artifact_confidence` =
  `v.confidence`, then `save(update_fields=[…])`.

The IOC road's *primary* loop (`finalise_ioc_group`) still writes
`ioc_score`/`ioc_confidence` unconditionally; only its derived loop and this mail
path skip the whole block for a sticky level.

These fields already exist on `MailArtifact` (write-once defaults today). The
`_BAND_TO_IOC_LEVEL` / `_DERIVED_SCORE` / `_STICKY` maps live in
`score_process/scoring/apply.py` — import them (Phase B's final-review fix
already established `apply.py` importing from `derived_observables.py`; this is
the reverse direction and equally fine, or lift the three maps to a small
`score_process/scoring/bands.py` shared module — decide in the plan).

### 6. `mail_band_escalation` — is it enough?

Current: raises `verdict.result` to the worst `embedded[i].band`, appends one
rationale line, leaves `final_score` untouched (the AI/YARA/sandbox number still
owns it). That is exactly right for this design — `score_observable` has
*already* applied the Tier rules per observable, so the merge only needs
worst-of. **One tweak to evaluate in the plan:** when the mail's own verdict is
Inconclusive/thin and an embedded observable is Dangerous at high confidence,
`final_confidence` should probably rise to the embedded verdict's confidence
(mirror the IOC-road fix from Phase B). Gate this on the backtest.

## Data-flow walkthrough

Mail with body + one embedded URL `https://evil.example/login`:

1. `collect_signals`: body → YARA/AI signals → `score_case`. URL artifact
   processed for side effects but **not** turned into a `score_case` signal.
2. `score_case` → e.g. `Inconclusive, conf 40` (body alone is unremarkable).
3. `_apply_embedded_escalation`: the URL's reports — GTI (Tier 1) `malicious`
   @ conf 95, Urlscan (Tier 3) `suspicious`. `score_observable` → `Dangerous`
   (Rule 1: Tier-1 authoritative). `embedded = [Dangerous]`.
4. `mail_band_escalation(Inconclusive-verdict, [Dangerous])` → verdict band
   raised to `Dangerous`, rationale gains "GTI (authoritative) reports the URL
   malicious." `MailArtifact.artifact_level = malicious`.
5. `apply_verdict` → case `Dangerous`, rationale readable, `X-artifact` badged.

Contrast today: GTI-clean + Urlscan-suspicious on the same URL →
`compute_weighted_scores` averages them → a middling score → mail drifts
Suspicious off Tier-3 noise. New: `score_observable` Rule 2 (Tier-1 clean beats
Tier-3 noise) → the URL is `Safe`, no escalation.

## Edge cases

- **No embedded observables** (body-only mail) → `embedded == []` → `verdict`
  unchanged. Byte-for-byte the current path minus the (now-absent) embedded
  signals.
- **Embedded observable with only failed reports** → `svs` still built (a
  `Failure` report → `no-data` vote); `score_observable([no-data…])` →
  `Inconclusive` → doesn't escalate. Fine.
- **Deny-listed embedded URL** → today `_compute_deny_listed` already forces the
  whole case Dangerous *before* `score_case`. Unchanged — deny list still wins,
  and `_write_mail_artifact_level` respects `_STICKY`.
- **MailAddress artifacts** — usually carry no analyzer reports (StopForumSpam
  is the only one, and it's rarely enabled). `mail_observable_reports` yields
  them with `[]` reports → skipped. No behavior change.
- **Redo-analysis** (`FINALIZED → ANALYZING`) → `get_report` re-runs the whole
  branch; `_write_mail_artifact_level` overwrites levels (idempotent).
- **`score_case`'s malicious-vote denominator shrinks** — embedded-IOC scores
  leave `n_scored`. Intended: the vote override was a blunt instrument for
  embedded IOCs; the categorical path is the precise replacement. The labelled
  harness is the check that this nets out right.

## Regression strategy

This changes how **every mail case** is scored. Gate on:

1. **`backtest_scoring` management command** — run before and after against the
   stored corpus; diff the verdict distribution. A band shift on a labelled
   case must be explainable ("now correctly Safe — GTI-clean overrode Urlscan
   noise").
2. **The labelled accuracy harness** (`d018b476`, seeded from the 5
   GTI-comparison cases) — must not lose accuracy. If it does → ship the
   fallback (Tier multiplier in `compute_weighted_scores`) instead and
   re-scope.
3. **`score_process` full suite** green.
4. Live: send the phishing sample through greenmail→feeder→scoring on the dev
   stack; confirm the verdict + a readable rationale + badged `MailArtifact`s.

## Testing

- `mail_observable_reports(mail)` unit — builds the right triples from
  `mail_artifacts`, one query, buckets reports by FK id, folds `analyzed_url`.
- `_bucket_reports` unit — the extracted core still passes the existing
  `observable_reports` tests (refactor must be behavior-preserving for the IOC
  road).
- `_apply_embedded_escalation` — Tier-1 malicious URL escalates an Inconclusive
  mail to Dangerous; Tier-1 clean + Tier-3 suspicious does **not** escalate;
  no embedded observables → verdict untouched; sticky `MailArtifact` keeps its
  level; rationale lines land in `case.verdict_rationale`.
- `collect_signals` — for a mail case, an embedded URL's analyzer score is
  **not** among the `Signal`s fed to `score_case` (the change in §3).
- End-to-end (`test_derived_scoring_mail.py` extended) — a mail whose only
  signal of badness is an embedded Tier-1 verdict finalizes Dangerous with the
  rationale naming the analyzer.
- Regression: `test_engine.py`, `test_collect.py`, `test_mail_escalation.py`
  stay green (adjust only where the embedded-signal removal is the point).

## Rollout

- No migration.
- One commit series on a feature branch off `design/ioc-road-and-verdict-model`.
- Kill switch: none needed — but if the backtest is ambiguous, land behind a
  `get_config("scoring.mail_embedded_categorical", True)` flag so it can be
  flipped without a deploy, and remove the flag once the SOC confirms the
  verdict quality on real traffic.
- Fallback path documented above (Tier multiplier).
- `ArtifactIsX.times_sent` / observable `times_sent` no longer increment for
  mail-embedded observables when the flag is ON (the artifact-scoring loop is
  skipped). These feed admin display + a URL-handler heuristic only, not scoring.
