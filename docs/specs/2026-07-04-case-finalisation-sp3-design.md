# SP3 — Scoring Engine Redesign (pure core + fixed math)

**Status:** Design approved, pending spec review
**Date:** 2026-07-04
**Part of:** Case-finalisation modernization program (SP1 ✅ → SP2 ✅ → **SP3**)
**Depends on:** SP1 (lifecycle state machine + `reconcile_case`) and SP2 (typed
aggregation + idempotent finalisation), both merged on `feature/frontweb`.

## Context

SP1 unified the finalise path (`reconcile_case → reconcile_case_core →
finalise`) and SP2 replaced the description buckets with a typed
`CaseAggregate`. Both deliberately left the **scoring engine** — the
`get_report(case)` black box — untouched. SP3 modernizes it.

The current engine (`score_process/scoring/`) has these problems, confirmed by
reading the code:

1. **No pure, testable core.** `get_report` threads three shared mutable lists
   (`reports`, `total_scores`, `total_confidences`) plus an `is_malicious` int
   through ~10 functions (`process_file_ioc`/`process_mail`/`process_ioc`/
   `process_mail_artifact`/…), each doing DB reads *and* writes inline. The
   scoring math cannot be exercised without a database.
2. **Dead `is_malicious` threading.** The int is passed *by value* into the
   `process_*` functions and mutated locally (never propagates); `get_report`
   then recomputes it from the reports list afterward. Every function signature
   carries a parameter that does nothing.
3. **Plain-mean cross-artifact aggregation.** `_calculate_and_set_final_scores`
   averages per-artifact scores (`sum/len`). Weighting only happens *within* an
   artifact (`compute_weighted_scores`); across artifacts a single malicious IOC
   is diluted by many benign ones.
4. **No-signal → Suspicious.** `DEFAULT_SCORE = 5` maps to the `SUSPICIOUS`
   range (5–7). SP2 fixed the stored `Case.results` default; the *computed*
   default still lands on Suspicious.
5. **Scattered persistence.** `calculate_final_scores`, each `process_*`, and
   `save_case_results` all issue `case.save()` / artifact saves interleaved with
   computation — hard to reason about, impossible to unit-test the math.
6. **Confidence-scale inconsistency.** `compute_weighted_scores` multiplies
   confidence by 10 (line 67); `manage_ai_jobs` also `*10`; other paths treat
   confidence as 0–100 already. There is no single defined scale.

## Scope

**In:** the scoring *algorithm* and its structure — extract a pure, testable
core; fix cross-artifact aggregation, the no-signal default, the dead
`is_malicious` threading, and the confidence scale. Verdicts change; drift is
quantified by a parity backtest.

**Out:** per-artifact analyzer-report *persistence* (`create_and_save_report`,
`process_analyzer_reports`, `handle_failure`) — that is report I/O, not scoring,
and stays as-is. `manage_ai_jobs` (just fixed in the branch review). The
lifecycle/reconcile path (SP1) and KPI/description (SP2) are untouched except
that `update_case_results` folds into the new `apply_verdict`.

## Design decisions (user-approved)

| Decision | Choice |
|---|---|
| Goal | Refactor to pure core **and** fix scoring logic; verdicts change, quantified via backtest. |
| Cross-artifact aggregation | **Hybrid:** `base_score = max(worst_confident_artifact, weighted_mean_all)`. |
| AI classifier | **Keep replace-on-higher-confidence:** if `conf_ai > base_conf` → use `(score_ai, conf_ai)`. |
| Overrides | **Keep both:** deny-list → instant Dangerous (score 10); malicious-vote (`n_malicious ≥ max(1, n_scored//3)`) → Dangerous. |
| Inconclusive | `final_score == 5` **OR** `final_conf < CONF_FLOOR` → Inconclusive (overrides still win). |

## Architecture (Approach A — pure core + collect/apply adapters)

```
get_report(case)                       # thin orchestrator (side-effecting)
  ├─ signals, ai, deny_listed = collect_signals(case)   # DB reads → typed inputs
  ├─ verdict = score_case(signals, ai, deny_listed)     # PURE — no DB
  └─ apply_verdict(case, verdict)                        # persist + KPI + notify
```

Three units, each with one purpose and a defined interface:

### 1. `scoring/engine.py` — pure, no DB

```python
from dataclasses import dataclass
from case_handler.models import Result

# Confidence normalized to 0–100 everywhere in the engine.
CONF_FLOOR   = 50      # below this → Inconclusive (pinned during backtest)
NEUTRAL      = 5
MALICIOUS_SCORE_THRESHOLD = 8


@dataclass(frozen=True)
class Signal:
    source: str          # "file", "mail_header", "url", … (diagnostic only)
    score: float         # 0–10 (already weight-aggregated WITHIN the artifact
                         #        by compute_weighted_scores, which consumes
                         #        Analyzer.weight — kept)
    confidence: float    # 0–100 (normalized). Doubles as the CROSS-artifact
                         #        weight: high-confidence signals pull the mean.
    is_malicious: bool   # set at collect time: level in {malicious,dangerous}
                         #        or score >= MALICIOUS_SCORE_THRESHOLD
    is_failure: bool


@dataclass(frozen=True)
class AiSignal:
    score: float         # 0–10
    confidence: float    # 0–100


@dataclass(frozen=True)
class CaseVerdict:
    final_score: float
    final_confidence: float
    result: str          # Result.* value
    n_malicious: int
    n_scored: int


def band(score: float) -> str:
    if score <= 4:  return Result.SAFE
    if score <= 7:  return Result.SUSPICIOUS
    return Result.DANGEROUS


def score_case(signals, ai=None, deny_listed=False) -> CaseVerdict:
    scored = [s for s in signals if not s.is_failure]
    if not scored:
        # Nothing ran / everything failed — SP1 invariant: honest Failure.
        return CaseVerdict(NEUTRAL, 0, Result.FAILURE, 0, 0)

    conf_sum  = sum(s.confidence for s in scored) or 1
    confident = [s.score for s in scored if s.confidence >= CONF_FLOOR]
    worst     = max(confident, default=0)
    wmean     = sum(s.score * s.confidence for s in scored) / conf_sum  # confidence-weighted
    base_score = max(worst, wmean)
    base_conf  = max(s.confidence for s in scored)     # case is as confident as its strongest signal

    # AI: replace-on-higher-confidence (kept behaviour).
    if ai is not None and ai.confidence > base_conf:
        final_score, final_conf = ai.score, ai.confidence
    else:
        final_score, final_conf = base_score, base_conf

    n_malicious = sum(1 for s in scored if s.is_malicious)   # per-artifact vote
    n_scored    = len(scored)

    # Overrides, strongest first.
    if deny_listed:
        result, final_score = Result.DANGEROUS, 10
    elif n_malicious >= max(1, n_scored // 3):
        result = Result.DANGEROUS
    elif round(final_score) == NEUTRAL or final_conf < CONF_FLOOR:
        result = Result.INCONCLUSIVE
    else:
        result = band(final_score)

    return CaseVerdict(
        final_score=min(round(final_score), 10),
        final_confidence=min(round(final_conf), 100),
        result=result,
        n_malicious=n_malicious,
        n_scored=n_scored,
    )
```

No DB, no `case`, no mutation of inputs. Fully unit-testable.

### 2. `scoring/collect.py` — DB reads → typed inputs

`collect_signals(case) -> (list[Signal], AiSignal | None, bool)` gathers what
the pure core needs. This absorbs the read-side logic currently smeared across
`process_file_ioc`/`process_mail`/`process_ioc`/`process_mail_artifact` and the
deny-list detection in `calculate_final_scores`:

- Walk the case's file / mail parts / attachments / mail artifacts / non-file
  IOCs exactly as `process_mail` etc. do today, but **emit a `Signal` per scored
  artifact** (normalizing confidence to 0–100) instead of appending to shared
  lists. Reuse `get_analyzer_reports_by_type_and_artifact` +
  `compute_weighted_scores` (kept) to get per-artifact score/confidence/weight.
- Build the `AiSignal` from `case.score_ai` / `case.confidence_ai` (already
  populated by `manage_ai_jobs`, which `get_report` calls before scoring).
- Compute `deny_listed` via the existing `get_deny_listed_domains_set` +
  `_check_mail_artifacts_for_deny_list` / `_is_address_deny_listed` (moved here).

The per-artifact **analyzer-report persistence** (`process_analyzer_reports` →
`create_and_save_report`) still runs during collection — that is report I/O, out
of scope — but the artifact **scoring-field writes** (`file_score`, `ioc_score`,
`update_artifact_with_scores`, …) stay where they are today. `collect_signals`
performs DB reads plus those existing artifact writes; it does **not** touch the
`Case` row. All `Case`-field persistence moves to `apply_verdict`.

### 3. `scoring/apply.py` — persist verdict + side-effects

`apply_verdict(case, verdict)` is the only place the `Case` scoring fields are
written:

```python
def apply_verdict(case, verdict):
    case.final_score      = verdict.final_score
    case.final_confidence = verdict.final_confidence
    case.score            = verdict.final_score       # legacy mirror
    case.confidence       = verdict.final_confidence
    case.results          = verdict.result
    case.analysis_done    = verdict.n_scored
    case.save(update_fields=[
        "final_score", "final_confidence", "score", "confidence",
        "results", "analysis_done",
    ])
    save_case_results(case, mail)          # MailInfo flags (kept; mail-less safe)
    update_kpi_and_user_stats(case)        # idempotent (SP2)
```

This replaces `update_case_results` + the `case.save` inside
`_calculate_and_set_final_scores`. `finalise` (SP1) still calls its own full
`case.save()` afterward for description + mail-less persistence — unchanged.

### `get_report` after SP3

```python
@staticmethod
def get_report(case) -> None:
    if not case:
        return
    try:
        _persist_analyzer_reports(case)        # existing report I/O + manage_ai_jobs
        signals, ai, deny_listed = collect_signals(case)
        verdict = score_case(signals, ai, deny_listed)
        apply_verdict(case, verdict)
    except Exception as exc:
        update_cases_logger.error("get_report: case %s: %s", case.id, exc, exc_info=True)
```

## Data flow (after SP3)

```
finalise(case)                          # SP1
  └─ get_report(case)
       ├─ persist analyzer reports + manage_ai_jobs   # report I/O (unchanged)
       ├─ signals, ai, deny_listed = collect_signals(case)   # reads
       ├─ verdict = score_case(...)                    # PURE
       └─ apply_verdict(case, verdict)                 # Case writes + KPI + notify
```

## Confidence scale

The engine defines confidence as **0–100**. `collect_signals` normalizes every
per-artifact confidence to that scale at the boundary (the current `*10` in
`compute_weighted_scores` produces 0–100 already for weights summing to the
analyzer count; the AI path `confidence_ai` is `analyzer.confidence * 10`, also
0–100). `CONF_FLOOR = 50` is the initial value; **pinned during the backtest**
so the Inconclusive band is tuned, not guessed.

## Parity backtest (safety net for verdict drift)

A management command `backtest_scoring` (in `score_process/management/commands/`)
replays historical cases through the new `score_case` and reports drift:

- For each finalised `Case`, rebuild `Signal`s from its persisted
  `AnalyzerReport`s (read-only; no re-running analyzers), run `score_case`, and
  compare the new `result` against the stored `case.results`.
- Emit a table: `case_id, old_result, new_result, Δfinal_score`, plus a summary
  matrix (how many Safe→Suspicious, Suspicious→Inconclusive, etc.).
- **Read-only** — never writes to any `Case`. Run before merge; cases that flip
  Safe↔Dangerous get eyeballed. `CONF_FLOOR` and any threshold are tuned against
  this report.

(Comparing against a git-stashed copy of the *old* engine is unnecessary: the
stored `case.results` already IS the old engine's output, so the backtest diffs
new-engine output against the recorded old-engine verdict directly.)

## Error handling

- `score_case` is pure and total: empty → Failure; zero total weight → guarded
  by `or 1`; no exception path of its own.
- `collect_signals` and `apply_verdict` inherit `get_report`'s existing
  try/except (logs + swallows), which sits inside `finalise` →
  `reconcile_case` (per-case isolation, SP1).

## Testing strategy

- **`score_case` (pure, no DB, table-driven):** empty signals → Failure; hybrid
  picks `max(worst, wmean)`; a lone high-confidence malicious signal survives
  dilution; AI override fires only when `conf_ai > base_conf`; override
  precedence (deny-list > malicious-vote > inconclusive > band); Inconclusive on
  `score==5` and on `conf<FLOOR`; band edges (4→Safe, 5→Inconclusive, 6/7→
  Suspicious, 8→Dangerous).
- **`collect_signals` (integration):** a built mail case with mixed
  analyzer reports produces the expected `Signal` list + `AiSignal` +
  `deny_listed`.
- **`apply_verdict` (integration):** writes exactly the six `Case` fields;
  MailInfo flags set; KPI counted once (SP2 idempotency holds).
- **Backtest command:** produces a drift report on the test DB fixtures.
- **Regression:** existing `finalise`/`reconcile_core` tests stay green (they
  mock `get_report`, so the seam is preserved).

## Rollout

No schema change — SP3 is code-only (the `Case` scoring fields already exist).
No migration. The only analyst-visible change is verdict drift, quantified by
the backtest before merge. `CampaignDomainAllowList` remains unioned into the
deny-list set (treated as intentional: "campaign" = active phishing campaign =
known-bad); flag if that is actually an allow-means-safe bug.

## Self-review notes

- Placeholder scan: none — every unit has concrete code.
- Consistency: `Signal`/`AiSignal`/`CaseVerdict` fields used identically across
  engine, collect, apply, and tests. `CONF_FLOOR`/`NEUTRAL`/
  `MALICIOUS_SCORE_THRESHOLD` are the single constants.
- Scope: single implementation plan; three new focused modules + one command.
- Ambiguity: confidence scale pinned to 0–100; override precedence explicit.
