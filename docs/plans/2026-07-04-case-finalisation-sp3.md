# Case Finalisation SP3 — Scoring Engine Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the DB-coupled `get_report` scoring black box with a pure,
unit-testable core (`score_case`) fed by a read-only `collect_signals` and
persisted by an idempotent `apply_verdict`, fixing cross-artifact aggregation,
the no-signal default, dead `is_malicious` threading, and the confidence scale.

**Architecture:** Three focused modules under `score_process/scoring/`:
`engine.py` (pure — `Signal`/`AiSignal`/`CaseVerdict`/`band`/`score_case`, no
DB), `collect.py` (`collect_signals(case) → (signals, ai, deny_listed)` — DB
reads + existing artifact-score writes), `apply.py` (`apply_verdict(case,
verdict)` — the only writer of `Case` scoring fields). `get_report` becomes a
3-line orchestrator: collect → score → apply. A read-only `backtest_scoring`
command quantifies verdict drift before merge.

**Tech Stack:** Django 5, Celery, MariaDB 11.4, Python 3.12, frozen dataclasses.
Tests run in-container (see Global Constraints).

## Global Constraints

- **Spec:** `docs/specs/2026-07-04-case-finalisation-sp3-design.md`. Every task's
  requirements implicitly include it.
- **Depends on:** SP1 + SP2, merged on `feature/frontweb`. `Case.results` default
  is already `Inconclusive`; KPI is already idempotent via `Case.kpi_counted`.
- **Confidence scale is 0–100** everywhere in the engine. `collect_signals`
  normalizes at the boundary.
- **Constants (single source, in `engine.py`):** `CONF_FLOOR = 50`,
  `NEUTRAL = 5`, `MALICIOUS_SCORE_THRESHOLD = 8`.
- **`Result` values** (`case_handler.models.Result`): `SAFE="Safe"`,
  `INCONCLUSIVE="Inconclusive"`, `FAILURE="Failure"`, `SUSPICIOUS="Suspicious"`,
  `DANGEROUS="Dangerous"`.
- **No schema change / no migration** — the `Case` scoring fields
  (`final_score`, `final_confidence`, `score`, `confidence`, `results`,
  `analysis_done`, `score_ai`, `confidence_ai`) all already exist.
- **Keep** the per-artifact analyzer-report *persistence*
  (`process_analyzer_reports`, `create_and_save_report`, `handle_failure`) and
  the per-artifact score writers (`update_artifact_with_scores`,
  `update_file_with_scores`, `update_mail_part_with_scores`,
  `compute_weighted_scores`, `get_analyzer_reports_by_type_and_artifact`). SP3
  only replaces the *cross-artifact scoring math* and the persistence of `Case`
  fields.
- **Container test recipe** (baked `/app`, not mounted): copy changed files in,
  then run tests. App root in the container is `/app/Suspicious`.
  ```bash
  cd deployment
  docker compose cp ../Suspicious/Suspicious/<path> suspicious:/app/Suspicious/<path>
  docker compose exec -T suspicious python manage.py test <targets> --keepdb -v1
  ```
  `docker compose cp` targets the `suspicious` container only (not
  `suspicious_celery`); rebuild + recreate both for live verification (Task 6).
- **Lint:** `ruff check Suspicious/` must pass before each commit.
- **TDD:** red → green → commit per task. Frequent commits.

---

### Task 1: Pure scoring engine (`engine.py`)

**Files:**
- Create: `Suspicious/Suspicious/score_process/scoring/engine.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_engine.py`

**Interfaces:**
- Consumes: `case_handler.models.Result` (the `TextChoices` values).
- Produces:
  - `Signal(source: str, score: float, confidence: float, is_malicious: bool, is_failure: bool)` — frozen dataclass.
  - `AiSignal(score: float, confidence: float)` — frozen dataclass.
  - `CaseVerdict(final_score: float, final_confidence: float, result: str, n_malicious: int, n_scored: int)` — frozen dataclass.
  - `band(score: float) -> str`
  - `score_case(signals: list[Signal], ai: AiSignal | None = None, deny_listed: bool = False) -> CaseVerdict`
  - Constants `CONF_FLOOR`, `NEUTRAL`, `MALICIOUS_SCORE_THRESHOLD`.

- [ ] **Step 1: Write the failing tests**

```python
# score_process/tests/test_engine.py
from django.test import SimpleTestCase
from case_handler.models import Result
from score_process.scoring.engine import (
    Signal, AiSignal, CaseVerdict, band, score_case,
    CONF_FLOOR, NEUTRAL,
)


def sig(score, conf, mal=False, fail=False, src="x"):
    return Signal(source=src, score=score, confidence=conf, is_malicious=mal, is_failure=fail)


class BandTest(SimpleTestCase):
    def test_bands(self):
        self.assertEqual(band(0), Result.SAFE)
        self.assertEqual(band(4), Result.SAFE)
        self.assertEqual(band(5), Result.SUSPICIOUS)   # band() alone; neutral handled in score_case
        self.assertEqual(band(7), Result.SUSPICIOUS)
        self.assertEqual(band(8), Result.DANGEROUS)
        self.assertEqual(band(10), Result.DANGEROUS)


class ScoreCaseTest(SimpleTestCase):
    def test_no_signals_is_failure(self):
        v = score_case([])
        self.assertEqual(v.result, Result.FAILURE)
        self.assertEqual((v.n_scored, v.final_confidence), (0, 0))

    def test_all_failures_is_failure(self):
        v = score_case([sig(9, 90, fail=True)])
        self.assertEqual(v.result, Result.FAILURE)
        self.assertEqual(v.n_scored, 0)

    def test_hybrid_takes_max_of_worst_and_wmean(self):
        # one high-confidence malicious signal must not be diluted by benign ones
        signals = [sig(9, 90, mal=True), sig(1, 80), sig(1, 80)]
        v = score_case(signals)
        # worst-confident = 9; wmean = (9*90+1*80+1*80)/250 = 3.64 → base = 9
        self.assertEqual(v.final_score, 9)
        self.assertEqual(v.result, Result.DANGEROUS)

    def test_low_confidence_worst_ignored_for_worst_but_counts_in_mean(self):
        # a score-9 signal below CONF_FLOOR does not drive `worst`
        v = score_case([sig(9, CONF_FLOOR - 1), sig(2, 90)])
        # worst-confident = 2 (only the conf-90 one qualifies); wmean pulls low
        self.assertLess(v.final_score, 8)

    def test_neutral_score_is_inconclusive(self):
        v = score_case([sig(5, 90)])
        self.assertEqual(v.result, Result.INCONCLUSIVE)

    def test_low_confidence_is_inconclusive(self):
        v = score_case([sig(7, CONF_FLOOR - 1)])
        self.assertEqual(v.result, Result.INCONCLUSIVE)

    def test_deny_list_overrides_to_dangerous(self):
        v = score_case([sig(1, 90)], deny_listed=True)
        self.assertEqual(v.result, Result.DANGEROUS)
        self.assertEqual(v.final_score, 10)

    def test_malicious_vote_forces_dangerous(self):
        # 2 malicious of 3 ≥ max(1, 3//3=1) → Dangerous even if mean is modest
        signals = [sig(6, 90, mal=True), sig(6, 90, mal=True), sig(1, 90)]
        v = score_case(signals)
        self.assertEqual(v.result, Result.DANGEROUS)
        self.assertEqual(v.n_malicious, 2)

    def test_ai_override_when_more_confident(self):
        # base_conf = 40; AI conf 90 > 40 → AI score wins
        v = score_case([sig(1, 40)], ai=AiSignal(score=9, confidence=90))
        self.assertEqual(v.final_score, 9)
        self.assertEqual(v.result, Result.DANGEROUS)

    def test_ai_ignored_when_less_confident(self):
        v = score_case([sig(2, 95)], ai=AiSignal(score=9, confidence=10))
        self.assertEqual(v.final_score, 2)
        self.assertEqual(v.result, Result.SAFE)

    def test_safe_case(self):
        v = score_case([sig(1, 90), sig(2, 90)])
        self.assertEqual(v.result, Result.SAFE)
```

- [ ] **Step 2: Run to verify it fails**

Run:
```bash
cd deployment
docker compose cp ../Suspicious/Suspicious/score_process/tests/test_engine.py suspicious:/app/Suspicious/score_process/tests/test_engine.py
docker compose exec -T suspicious python manage.py test score_process.tests.test_engine --keepdb -v1
```
Expected: FAIL — `ModuleNotFoundError: No module named 'score_process.scoring.engine'`.

- [ ] **Step 3: Write the engine**

```python
# score_process/scoring/engine.py
"""Pure, DB-free case-scoring core. No Django models are queried or mutated
here — inputs are plain dataclasses, output is a CaseVerdict."""
from dataclasses import dataclass

from case_handler.models import Result

CONF_FLOOR = 50                 # below this a signal can't drive `worst`; a
                                # case below this is Inconclusive. Pinned in Task 6.
NEUTRAL = 5
MALICIOUS_SCORE_THRESHOLD = 8


@dataclass(frozen=True)
class Signal:
    source: str
    score: float          # 0–10, already weight-aggregated within the artifact
    confidence: float     # 0–100; doubles as the cross-artifact mean weight
    is_malicious: bool
    is_failure: bool


@dataclass(frozen=True)
class AiSignal:
    score: float          # 0–10
    confidence: float     # 0–100


@dataclass(frozen=True)
class CaseVerdict:
    final_score: float
    final_confidence: float
    result: str
    n_malicious: int
    n_scored: int


def band(score: float) -> str:
    if score <= 4:
        return Result.SAFE
    if score <= 7:
        return Result.SUSPICIOUS
    return Result.DANGEROUS


def score_case(signals, ai=None, deny_listed=False) -> CaseVerdict:
    scored = [s for s in signals if not s.is_failure]
    if not scored:
        return CaseVerdict(NEUTRAL, 0, Result.FAILURE, 0, 0)

    conf_sum = sum(s.confidence for s in scored) or 1
    worst = max((s.score for s in scored if s.confidence >= CONF_FLOOR), default=0)
    wmean = sum(s.score * s.confidence for s in scored) / conf_sum
    base_score = max(worst, wmean)
    base_conf = max(s.confidence for s in scored)

    if ai is not None and ai.confidence > base_conf:
        final_score, final_conf = ai.score, ai.confidence
    else:
        final_score, final_conf = base_score, base_conf

    n_malicious = sum(1 for s in scored if s.is_malicious)
    n_scored = len(scored)

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

- [ ] **Step 4: Run to verify it passes**

Run:
```bash
docker compose cp ../Suspicious/Suspicious/score_process/scoring/engine.py suspicious:/app/Suspicious/score_process/scoring/engine.py
docker compose exec -T suspicious python manage.py test score_process.tests.test_engine --keepdb -v1
```
Expected: PASS (12 tests). Then `ruff check Suspicious/Suspicious/score_process/scoring/engine.py` → All checks passed.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/engine.py \
        Suspicious/Suspicious/score_process/tests/test_engine.py
git commit -m "feat(scoring): pure score_case engine (Signal/CaseVerdict)"
```

---

### Task 2: Signal collection (`collect.py`)

**Files:**
- Create: `Suspicious/Suspicious/score_process/scoring/collect.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_collect.py`

**Interfaces:**
- Consumes: `Signal`, `AiSignal`, `MALICIOUS_SCORE_THRESHOLD` from Task 1;
  existing `process_file_ioc`/`process_mail`/`process_ioc` (they still persist
  analyzer reports + artifact scores and append per-artifact `(score,
  confidence)` to the two lists passed in); existing deny-list helpers
  `get_deny_listed_domains_set`, `_check_mail_artifacts_for_deny_list`,
  `_is_address_deny_listed` from `case_score_calculation.py`.
- Produces: `collect_signals(case) -> tuple[list[Signal], AiSignal | None, bool]`.

**Design note:** the existing `process_*` functions append parallel
`total_scores` / `total_confidences` entries per artifact but do not expose
per-artifact `level`. SP3 derives `Signal.is_malicious` from the artifact's
aggregated score (`score >= MALICIOUS_SCORE_THRESHOLD`) — the per-artifact
equivalent of today's per-report vote (intentional change, see spec). Failed
artifacts are not appended to the lists by `process_*`; `collect_signals`
tracks the failure count returned by `process_*` and emits that many
`is_failure=True` signals so `score_case`'s empty→Failure branch still fires
for all-failed cases.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_collect.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail, CaseHasNonFileIocs
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from score_process.scoring.collect import collect_signals
from score_process.scoring.engine import Signal


class CollectSignalsTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="cs_u", password="x")

    def test_ioc_only_case_yields_one_signal(self):
        ip = IP.objects.create(address="203.0.113.7")
        analyzer = Analyzer.objects.create(name="Abuse", analyzer_cortex_id="Abuse", weight=1)
        AnalyzerReport.objects.create(
            cortex_job_id="j1", type="ip", status="Success", analyzer=analyzer,
            ip=ip, level="malicious", confidence=9, score=9,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        iocs = CaseHasNonFileIocs.objects.create(ip=ip)
        case = Case.objects.create(description="", reporter=self.user, nonFileIocs=iocs)

        signals, ai, deny_listed = collect_signals(case)

        self.assertTrue(all(isinstance(s, Signal) for s in signals))
        self.assertEqual(len(signals), 1)
        self.assertTrue(signals[0].is_malicious)     # score 9 ≥ 8
        self.assertFalse(deny_listed)

    def test_no_iocs_yields_no_signals(self):
        case = Case.objects.create(description="", reporter=self.user)
        signals, ai, deny_listed = collect_signals(case)
        self.assertEqual(signals, [])
        self.assertFalse(deny_listed)
```

*(The exact non-null fields on `IP`, `Analyzer`, and `AnalyzerReport` may differ
— the implementer MUST introspect the models first (e.g.
`docker compose exec -T suspicious python manage.py shell -c "from cortex_job.models import AnalyzerReport; print([f.name for f in AnalyzerReport._meta.get_fields()])"`)
and adjust fixture fields accordingly. `Analyzer.weight` is required by
`compute_weighted_scores`.)*

- [ ] **Step 2: Run to verify it fails**

Run:
```bash
docker compose cp ../Suspicious/Suspicious/score_process/tests/test_collect.py suspicious:/app/Suspicious/score_process/tests/test_collect.py
docker compose exec -T suspicious python manage.py test score_process.tests.test_collect --keepdb -v1
```
Expected: FAIL — `No module named 'score_process.scoring.collect'`.

- [ ] **Step 3: Write `collect.py`**

```python
# score_process/scoring/collect.py
"""Read the DB and build the typed inputs the pure engine consumes.

Reuses the existing per-artifact processing (which still persists analyzer
reports and artifact scores) but converts its parallel score/confidence output
into Signal objects, plus the AI signal and the deny-list flag.
"""
import logging

from score_process.scoring.engine import Signal, AiSignal, MALICIOUS_SCORE_THRESHOLD
from score_process.scoring.processing import (
    process_file_ioc, process_mail, process_ioc,
)
from score_process.scoring.case_score_calculation import (
    get_deny_listed_domains_set,
    _check_mail_artifacts_for_deny_list,
    _is_address_deny_listed,
)

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def _signals_from(scores, confidences, offset, source):
    """Turn the new (score, confidence) pairs appended since `offset` into
    Signals. is_malicious is the per-artifact equivalent of the old per-report
    vote."""
    out = []
    for score, conf in zip(scores[offset:], confidences[offset:]):
        out.append(Signal(
            source=source, score=score, confidence=conf,
            is_malicious=score >= MALICIOUS_SCORE_THRESHOLD, is_failure=False,
        ))
    return out


def collect_signals(case):
    reports, scores, confidences = [], [], []
    signals = []
    failures = 0

    if case.fileOrMail:
        file = getattr(case.fileOrMail, "file", None)
        if file:
            off = len(scores)
            failures += process_file_ioc(file, reports, scores, confidences, 0, case.id)
            signals += _signals_from(scores, confidences, off, "file")

        mail = getattr(case.fileOrMail, "mail", None)
        if mail:
            off = len(scores)
            failures += process_mail(mail, reports, scores, confidences, 0, case.id)
            signals += _signals_from(scores, confidences, off, "mail")

    if case.nonFileIocs:
        ioc_data = case.nonFileIocs.get_iocs()
        for ioc_type in ("url", "ip", "hash", "domain"):
            ioc = ioc_data.get(ioc_type)
            if ioc:
                off = len(scores)
                failures += process_ioc(ioc, ioc_type, reports, scores, confidences, 0)
                signals += _signals_from(scores, confidences, off, ioc_type)

    # Emit a failure Signal per failed artifact so all-failed cases → Failure.
    signals += [Signal("failed", 0, 0, False, True) for _ in range(failures)]

    ai = None
    if getattr(case, "confidence_ai", 0):
        ai = AiSignal(score=case.score_ai or 0, confidence=case.confidence_ai or 0)

    deny_listed = _compute_deny_listed(case)
    return signals, ai, deny_listed


def _compute_deny_listed(case) -> bool:
    deny = get_deny_listed_domains_set()
    if case.fileOrMail and case.fileOrMail.mail:
        if _check_mail_artifacts_for_deny_list(case.fileOrMail.mail, deny, logger):
            return True
    if case.nonFileIocs and getattr(case.nonFileIocs, "url", None):
        if _is_address_deny_listed(case.nonFileIocs.url.address, deny, logger):
            return True
    return False
```

- [ ] **Step 4: Run to verify it passes**

Run:
```bash
docker compose cp ../Suspicious/Suspicious/score_process/scoring/collect.py suspicious:/app/Suspicious/score_process/scoring/collect.py
docker compose exec -T suspicious python manage.py test score_process.tests.test_collect --keepdb -v1
```
Expected: PASS. Then `ruff check Suspicious/Suspicious/score_process/scoring/collect.py`.

*(If the deny-list helpers are named/private differently, adjust imports — grep
`case_score_calculation.py` first. `_is_address_deny_listed`,
`_check_mail_artifacts_for_deny_list`, `get_deny_listed_domains_set` are the
current names.)*

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/collect.py \
        Suspicious/Suspicious/score_process/tests/test_collect.py
git commit -m "feat(scoring): collect_signals — DB reads to typed engine inputs"
```

---

### Task 3: Verdict application (`apply.py`)

**Files:**
- Create: `Suspicious/Suspicious/score_process/scoring/apply.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_apply.py`

**Interfaces:**
- Consumes: `CaseVerdict` (Task 1); existing `save_case_results` and
  `update_kpi_and_user_stats` from `score_process.scoring.update_handler`.
- Produces: `apply_verdict(case, verdict) -> None` — the sole writer of the six
  `Case` scoring fields.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_apply.py
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, Result
from score_process.scoring.apply import apply_verdict
from score_process.scoring.engine import CaseVerdict


class ApplyVerdictTest(TestCase):
    def test_writes_case_fields(self):
        user = get_user_model().objects.create_user(username="ap_u", password="x")
        case = Case.objects.create(description="", reporter=user)
        v = CaseVerdict(final_score=9, final_confidence=90,
                        result=Result.DANGEROUS, n_malicious=2, n_scored=4)
        apply_verdict(case, v)
        case.refresh_from_db()
        self.assertEqual(case.results, Result.DANGEROUS)
        self.assertEqual(case.final_score, 9)
        self.assertEqual(case.final_confidence, 90)
        self.assertEqual(case.analysis_done, 4)
        self.assertTrue(case.kpi_counted)     # SP2 idempotent KPI ran once
```

- [ ] **Step 2: Run to verify it fails**

Run:
```bash
docker compose cp ../Suspicious/Suspicious/score_process/tests/test_apply.py suspicious:/app/Suspicious/score_process/tests/test_apply.py
docker compose exec -T suspicious python manage.py test score_process.tests.test_apply --keepdb -v1
```
Expected: FAIL — `No module named 'score_process.scoring.apply'`.

- [ ] **Step 3: Write `apply.py`**

```python
# score_process/scoring/apply.py
"""Persist a CaseVerdict onto the Case and fire finalisation side-effects.
The only place Case scoring fields are written by the scoring path."""
from score_process.scoring.update_handler import (
    save_case_results, update_kpi_and_user_stats,
)


def apply_verdict(case, verdict) -> None:
    case.final_score = verdict.final_score
    case.final_confidence = verdict.final_confidence
    case.score = verdict.final_score          # legacy mirror
    case.confidence = verdict.final_confidence
    case.results = verdict.result
    case.analysis_done = verdict.n_scored
    case.save(update_fields=[
        "final_score", "final_confidence", "score", "confidence",
        "results", "analysis_done",
    ])

    mail = getattr(case.fileOrMail, "mail", None) if case.fileOrMail else None
    save_case_results(case, mail)             # MailInfo flags (mail-less safe)
    update_kpi_and_user_stats(case)           # idempotent (SP2)
```

- [ ] **Step 4: Run to verify it passes**

Run:
```bash
docker compose cp ../Suspicious/Suspicious/score_process/scoring/apply.py suspicious:/app/Suspicious/score_process/scoring/apply.py
docker compose exec -T suspicious python manage.py test score_process.tests.test_apply --keepdb -v1
```
Expected: PASS. Then `ruff check Suspicious/Suspicious/score_process/scoring/apply.py`.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/apply.py \
        Suspicious/Suspicious/score_process/tests/test_apply.py
git commit -m "feat(scoring): apply_verdict — sole writer of Case scoring fields"
```

---

### Task 4: Rewire `get_report` + delete the old cross-artifact math

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/cortex_analyzers/reports.py` (`get_report`)
- Modify: `Suspicious/Suspicious/score_process/scoring/case_score_calculation.py` (delete `calculate_final_scores` + `_calculate_and_set_final_scores`; keep deny-list helpers + `calculate_result_ranges`/`get_score_level` unless proven dead)
- Modify: `Suspicious/Suspicious/score_process/scoring/update_handler.py` (`update_case_results` no longer called by `get_report`; leave the function if other callers exist — grep first)
- Test: existing `cortex_job`/`tasp` finalise tests must stay green (they mock `get_report`).

**Interfaces:**
- Consumes: `collect_signals` (Task 2), `score_case` (Task 1), `apply_verdict` (Task 3).
- Produces: `get_report(case)` with the same signature and side-effects
  (verdict persisted, KPI counted, notification fired) via the new path.

- [ ] **Step 1: Prove what the old math’s only caller is**

Run:
```bash
grep -rnE "calculate_final_scores|_calculate_and_set_final_scores|update_case_results" Suspicious/Suspicious --include=*.py | grep -v /tests/
```
Record every hit. `calculate_final_scores` should be called only by
`get_report`. `update_case_results` likewise. If either has another live caller,
keep it and only remove the `get_report` call site.

- [ ] **Step 2: Rewrite `get_report`**

Replace the body of `CortexAnalyzerReports.get_report` (keep the analyzer-report
persistence + `manage_ai_jobs` that run before scoring) with:

```python
@staticmethod
def get_report(case) -> None:
    from score_process.scoring.collect import collect_signals
    from score_process.scoring.engine import score_case
    from score_process.scoring.apply import apply_verdict

    if not case:
        update_cases_logger.warning("get_report called with no case.")
        return
    try:
        signals, ai, deny_listed = collect_signals(case)
        verdict = score_case(signals, ai, deny_listed)
        apply_verdict(case, verdict)
        update_cases_logger.info(
            "get_report: case %s → %s (score=%s conf=%s, %d/%d malicious).",
            case.id, verdict.result, verdict.final_score,
            verdict.final_confidence, verdict.n_malicious, verdict.n_scored,
        )
    except Exception as exc:
        update_cases_logger.error(
            "get_report: error scoring case %s: %s", case.id, exc, exc_info=True
        )
```

**Note:** `collect_signals` internally runs the same `process_file_ioc`/
`process_mail`/`process_ioc` that persist analyzer reports, so the separate
persistence block in the old `get_report` is now redundant — delete it (its work
happens inside `collect_signals`). `manage_ai_jobs` must still run **before**
`collect_signals` so `case.confidence_ai`/`score_ai` are populated for the
`AiSignal`; call it explicitly at the top of the `try` for mail cases, or move
the `manage_ai_jobs(case)` call into `collect_signals` right after `process_mail`.
Pick one and make it explicit; the AI fields must be set before the `AiSignal`
is built. (Introspect: `manage_ai_jobs` full-saves `score_ai`/`confidence_ai`.)

- [ ] **Step 3: Delete the dead cross-artifact math**

If Step 1 proved no other callers: delete `calculate_final_scores` and
`_calculate_and_set_final_scores` from `case_score_calculation.py`, and remove
the `get_report` call to `update_case_results` (delete the function only if it
has no other caller). Remove now-unused imports (ruff F401). Keep
`get_deny_listed_domains_set`, `_check_mail_artifacts_for_deny_list`,
`_is_address_deny_listed`, `calculate_result_ranges`, `get_score_level`, and all
per-artifact writers.

- [ ] **Step 4: Run the affected suites — must stay green**

Run:
```bash
for f in score_process/scoring/cortex_analyzers/reports.py \
         score_process/scoring/case_score_calculation.py \
         score_process/scoring/update_handler.py; do
  docker compose cp ../Suspicious/Suspicious/$f suspicious:/app/Suspicious/$f
done
docker compose exec -T suspicious python manage.py test cortex_job tasp case_handler score_process --keepdb -v1
```
Expected: OK (0 failures). Then `ruff check Suspicious/Suspicious/score_process/`.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/
git commit -m "refactor(scoring): get_report = collect → score_case → apply; drop mean math"
```

---

### Task 5: Parity backtest command

**Files:**
- Create: `Suspicious/Suspicious/score_process/management/commands/backtest_scoring.py`
- Create (if missing): `Suspicious/Suspicious/score_process/management/__init__.py`, `.../commands/__init__.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_backtest.py`

**Interfaces:**
- Consumes: `Signal`, `score_case` (Task 1); `AnalyzerReport`, `Case`.
- Produces: a `backtest_scoring` management command that is **read-only** (never
  writes any `Case`) and prints a drift table + transition matrix.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_backtest.py
from io import StringIO
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from case_handler.models import Case


class BacktestTest(TestCase):
    def test_runs_read_only(self):
        user = get_user_model().objects.create_user(username="bt_u", password="x")
        case = Case.objects.create(description="", reporter=user, results="Suspicious")
        out = StringIO()
        call_command("backtest_scoring", stdout=out)
        case.refresh_from_db()
        self.assertEqual(case.results, "Suspicious")   # unchanged — read-only
        self.assertIn("old", out.getvalue().lower())    # header printed
```

- [ ] **Step 2: Run to verify it fails**

Run:
```bash
docker compose cp ../Suspicious/Suspicious/score_process/tests/test_backtest.py suspicious:/app/Suspicious/score_process/tests/test_backtest.py
docker compose exec -T suspicious python manage.py test score_process.tests.test_backtest --keepdb -v1
```
Expected: FAIL — `Unknown command: 'backtest_scoring'`.

- [ ] **Step 3: Write the command**

```python
# score_process/management/commands/backtest_scoring.py
"""Replay finalised cases through the new engine and report verdict drift.
Read-only: never writes a Case."""
from collections import Counter

from django.core.management.base import BaseCommand

from case_handler.models import Case
from cortex_job.models import AnalyzerReport
from score_process.scoring.engine import Signal, score_case, MALICIOUS_SCORE_THRESHOLD


def _signals_for(case):
    """Rebuild Signals from a case's persisted AnalyzerReports (best-effort:
    one Signal per successful report, using its stored score/confidence)."""
    signals = []
    reports = AnalyzerReport.objects.filter(
        cortex_job__case_links__case=case
    ) if hasattr(AnalyzerReport, "cortex_job") else AnalyzerReport.objects.none()
    for r in reports:
        if r.status == "Failure":
            signals.append(Signal("report", 0, 0, False, True))
            continue
        score = r.score or 0
        conf = (r.confidence or 0) * 10        # 0–10 → 0–100
        signals.append(Signal(
            "report", score, conf,
            is_malicious=score >= MALICIOUS_SCORE_THRESHOLD, is_failure=False,
        ))
    return signals


class Command(BaseCommand):
    help = "Backtest the new scoring engine against stored case verdicts (read-only)."

    def handle(self, *args, **options):
        matrix = Counter()
        n = 0
        self.stdout.write("case_id  old -> new  (Δscore)")
        for case in Case.objects.exclude(results="").iterator():
            signals = _signals_for(case)
            verdict = score_case(signals)
            old, new = case.results, verdict.result
            matrix[(old, new)] += 1
            n += 1
            if old != new:
                self.stdout.write(
                    f"{case.id}  {old} -> {new}  ({verdict.final_score})"
                )
        self.stdout.write("\nTransition matrix (old -> new: count):")
        for (old, new), count in sorted(matrix.items()):
            flag = "" if old == new else "  <-- CHANGED"
            self.stdout.write(f"  {old} -> {new}: {count}{flag}")
        self.stdout.write(f"\nScored {n} cases.")
```

*(The `AnalyzerReport → Case` join in `_signals_for` is a best-effort sketch:
the implementer MUST verify how reports link to a case — check the
`CaseAnalyzerJob` ledger (`cortex_job.models`) which maps `case ↔ cortex_job ↔
AnalyzerReport` — and use the real relation. The point of the command is the
drift table; the Signal-rebuild fidelity only needs to be good enough to
compare bands. This is why Task 6 eyeballs Safe↔Dangerous flips rather than
trusting the number blindly.)*

- [ ] **Step 4: Run to verify it passes**

Run:
```bash
docker compose cp ../Suspicious/Suspicious/score_process/management/commands/backtest_scoring.py suspicious:/app/Suspicious/score_process/management/commands/backtest_scoring.py
docker compose exec -T suspicious python manage.py test score_process.tests.test_backtest --keepdb -v1
```
Expected: PASS. Then `ruff check` the command file.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/management/
git add Suspicious/Suspicious/score_process/tests/test_backtest.py
git commit -m "feat(scoring): read-only backtest_scoring drift command"
```

---

### Task 6: Full-suite + backtest + tune + live verify

**Files:** none (verification + one constant tune).

- [ ] **Step 1: Full affected suite**

Run:
```bash
docker compose exec -T suspicious python manage.py test --keepdb -v1
```
Expected: OK (0 failures). Then `ruff check Suspicious/` → All checks passed.

- [ ] **Step 2: Rebuild image + recreate both containers**

```bash
cd deployment
docker compose build suspicious
docker compose up -d --force-recreate suspicious suspicious_celery
```
(No migration — SP3 is code-only.)

- [ ] **Step 3: Run the backtest + tune `CONF_FLOOR`**

```bash
docker compose exec -T suspicious python manage.py backtest_scoring | tee /tmp/sp3-drift.txt
```
Inspect the transition matrix. Eyeball every Safe↔Dangerous flip. If the
Inconclusive band is too wide/narrow, adjust `CONF_FLOOR` in `engine.py`
(re-copy + re-run) until the drift is defensible. Record the final matrix.

- [ ] **Step 4: Live spot-check**

Drive one zero-analyzer case and one scored case through `reconcile_case_core`
via the shell (as in SP2 T6) and confirm: zero-analyzer → `results="Failure"`;
a scored case → a sane `results` + populated `final_score`/`final_confidence`.
Clean up the test rows.

- [ ] **Step 5: Commit any tune + record results**

```bash
git add Suspicious/Suspicious/score_process/scoring/engine.py
git commit -m "chore(scoring): pin CONF_FLOOR from backtest drift" --allow-empty
```

---

## Self-Review

**Spec coverage:**
- Pure `score_case` engine → Task 1. ✓
- `collect_signals` reads → Task 2. ✓
- `apply_verdict` writes → Task 3. ✓
- `get_report` rewire + delete mean math + dead `is_malicious` → Task 4. ✓
- Confidence 0–100 normalization → Tasks 1 (defined) + 2 (boundary). ✓
- Hybrid `max(worst, wmean)`, AI override, deny-list + malicious-vote overrides,
  neutral/low-conf → Inconclusive → Task 1 (tested per branch). ✓
- Parity backtest → Task 5 + Task 6 Step 3. ✓
- No migration → stated in Global Constraints + Task 6. ✓

**Type consistency:** `Signal(source, score, confidence, is_malicious,
is_failure)`, `AiSignal(score, confidence)`, `CaseVerdict(final_score,
final_confidence, result, n_malicious, n_scored)`, `score_case(signals, ai,
deny_listed)`, `collect_signals(case) -> (signals, ai, deny_listed)`,
`apply_verdict(case, verdict)` — identical across Tasks 1–5.

**Placeholder scan:** none — every code step is concrete. Two flagged
introspection points (Task 2 fixture fields, Task 5 report→case join) are marked
explicitly because the exact ORM field names must be verified against the live
models, not guessed.

**Open confirmations for the implementer:** exact non-null fields on `IP`/
`Analyzer`/`AnalyzerReport` (Task 2); the real `AnalyzerReport ↔ Case` relation
via `CaseAnalyzerJob` (Task 5); whether `update_case_results`/
`calculate_result_ranges`/`get_score_level` retain other callers before deletion
(Task 4 Step 1).
