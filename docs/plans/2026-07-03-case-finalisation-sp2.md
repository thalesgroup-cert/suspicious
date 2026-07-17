# Case Finalisation SP2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the ~300-line string-ID-set aggregation buckets with a typed `CaseAggregate` from one `CaseAnalyzerJob` query, make KPI counting idempotent, and change the fail-dangerous `Case.results` default to `Inconclusive`.

**Architecture:** A new `aggregate_case(case) -> CaseAggregate` (single GROUP BY over the ledger) feeds `finalise()`/`_describe()`; the legacy `CortexJobManager` bucket machinery is deleted; `update_kpi_and_user_stats` guards on a new `Case.kpi_counted` flag; the `results` default is altered via migration.

**Tech Stack:** Django 5, MariaDB, Celery, dataclasses, `manage.py test`.

## Global Constraints

- Consumes SP1: `reconcile_case_core` → `finalise()` → `_describe()` in `Suspicious/Suspicious/cortex_job/cortex_utils/reconciliation.py`; `CortexAnalyzerReports.get_report` is the scoring black box (do NOT modify it — SP3).
- `CaseAnalyzerJob` statuses: `STATUS_WAITING="Waiting"`, `STATUS_INPROGRESS="InProgress"`, `STATUS_SUCCESS="Success"`, `STATUS_FAILURE="Failure"`, `STATUS_DELETED="Deleted"` (`cortex_job/models.py`). `PENDING_STATUSES=(Waiting, InProgress)`.
- **Name-collision guard:** delete only the **`CortexJobManager`** methods named `process_file`/`process_mail`/`process_iocs`/etc. The similarly-named `process_file_ioc`/`process_mail`/`process_ioc` in `score_process/scoring/processing.py` are used by `get_report` and MUST be kept.
- Latest case_handler migration is `0016_case_dispatched_at`; new migrations continue from there.
- Tests run in the container (baked `/app`, not mounted). From `/home/tbhang/suspicious/deployment`: `docker compose cp ../Suspicious/Suspicious/<relpath> suspicious:/app/Suspicious/<relpath>` then `docker compose exec -T suspicious python manage.py test <dotted.path> --keepdb -v1`. Generate migrations in the container and copy the file back to the host. Delete removed files from the container with `docker compose exec -T suspicious rm -f <path>`.
- Commit with explicit `git add <paths>` (never `git add -A`). Branch `feature/frontweb`.

---

### Task 1: `CaseAggregate` + `aggregate_case`

**Files:**
- Create: `Suspicious/Suspicious/cortex_job/cortex_utils/aggregate.py`
- Test: `Suspicious/Suspicious/cortex_job/tests/test_aggregate.py`

**Interfaces:**
- Consumes: `CaseAnalyzerJob` (case FK, `status`, `STATUS_*` constants).
- Produces: `cortex_job.cortex_utils.aggregate.CaseAggregate` (frozen dataclass: `total, success, failure, deleted, in_progress, waiting: int`; props `pending -> int`, `scored -> int`) and `aggregate_case(case) -> CaseAggregate`.

- [ ] **Step 1: Write the failing test**

```python
# cortex_job/tests/test_aggregate.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from cortex_job.cortex_utils.aggregate import CaseAggregate, aggregate_case


class CaseAggregateTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="agg_u", password="x")
        self.case = Case.objects.create(description="", reporter=self.user)
        self.analyzer = Analyzer.objects.create(name="A_1", cortex_name="A_1")

    def _job(self, status, jid):
        r = AnalyzerReport.objects.create(status=status, type="ip")
        return CaseAnalyzerJob.objects.create(
            case=self.case, cortex_job_id=jid, analyzer=self.analyzer,
            analyzer_report=r, status=status,
        )

    def test_counts_by_status(self):
        for i, s in enumerate(["Success", "Success", "Failure", "InProgress",
                               "Waiting", "Deleted"]):
            self._job(s, f"j{i}")
        agg = aggregate_case(self.case)
        self.assertEqual(agg.total, 6)
        self.assertEqual(agg.success, 2)
        self.assertEqual(agg.failure, 1)
        self.assertEqual(agg.in_progress, 1)
        self.assertEqual(agg.waiting, 1)
        self.assertEqual(agg.deleted, 1)
        self.assertEqual(agg.pending, 2)      # in_progress + waiting
        self.assertEqual(agg.scored, 5)       # total - deleted

    def test_zero_jobs(self):
        agg = aggregate_case(self.case)
        self.assertEqual((agg.total, agg.pending, agg.scored), (0, 0, 0))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose exec -T suspicious python manage.py test cortex_job.tests.test_aggregate --keepdb -v1`
Expected: FAIL — `ModuleNotFoundError: No module named 'cortex_job.cortex_utils.aggregate'`

(Before running: confirm the exact required fields for `Analyzer` / `AnalyzerReport` / `CaseAnalyzerJob` creation via `docker compose exec -T suspicious python manage.py shell -c "from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob; print([f.name for f in Analyzer._meta.fields]); print([f.name for f in AnalyzerReport._meta.fields])"` and adjust the `create(...)` kwargs to satisfy non-null fields. The aggregate logic only depends on `CaseAnalyzerJob.case` + `.status`.)

- [ ] **Step 3: Write minimal implementation**

```python
# cortex_job/cortex_utils/aggregate.py
from dataclasses import dataclass

from django.db.models import Count

from cortex_job.models import CaseAnalyzerJob


@dataclass(frozen=True)
class CaseAggregate:
    total: int
    success: int
    failure: int
    deleted: int
    in_progress: int
    waiting: int

    @property
    def pending(self) -> int:
        return self.in_progress + self.waiting

    @property
    def scored(self) -> int:
        """Terminal, non-deleted reports — the denominator for descriptions."""
        return self.total - self.deleted


_STATUS_FIELD = {
    CaseAnalyzerJob.STATUS_SUCCESS: "success",
    CaseAnalyzerJob.STATUS_FAILURE: "failure",
    CaseAnalyzerJob.STATUS_DELETED: "deleted",
    CaseAnalyzerJob.STATUS_INPROGRESS: "in_progress",
    CaseAnalyzerJob.STATUS_WAITING: "waiting",
}


def aggregate_case(case) -> CaseAggregate:
    counts = {v: 0 for v in _STATUS_FIELD.values()}
    total = 0
    rows = (
        CaseAnalyzerJob.objects
        .filter(case=case)
        .values("status")
        .annotate(n=Count("id"))
    )
    for row in rows:
        total += row["n"]
        field = _STATUS_FIELD.get(row["status"])
        if field:
            counts[field] = row["n"]
    return CaseAggregate(total=total, **counts)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `docker compose exec -T suspicious python manage.py test cortex_job.tests.test_aggregate --keepdb -v1`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/cortex_job/cortex_utils/aggregate.py \
        Suspicious/Suspicious/cortex_job/tests/test_aggregate.py
git commit -m "feat(aggregate): typed CaseAggregate from CaseAnalyzerJob ledger"
```

---

### Task 2: `finalise`/`_describe` consume `CaseAggregate`

**Files:**
- Modify: `Suspicious/Suspicious/cortex_job/cortex_utils/reconciliation.py`
- Modify: `Suspicious/Suspicious/cortex_job/tests/test_finalise.py`

**Interfaces:**
- Consumes: `aggregate_case`, `CaseAggregate` (Task 1); `CortexAnalyzerReports.get_report` (unchanged).
- Produces: `_describe(agg: CaseAggregate) -> str`; `finalise(case)` no longer calls `CortexJobManager.get_results`.

- [ ] **Step 1: Rewrite the `_describe` tests to use `CaseAggregate`**

Replace the `DescribeTest` class in `test_finalise.py` with:

```python
from cortex_job.cortex_utils.aggregate import CaseAggregate

def _agg(total=0, success=0, failure=0, deleted=0, in_progress=0, waiting=0):
    return CaseAggregate(total=total, success=success, failure=failure,
                         deleted=deleted, in_progress=in_progress, waiting=waiting)


class DescribeTest(TestCase):
    def test_no_scored_reports_mentions_no_analyzer(self):
        self.assertIn("analyzer", _describe(_agg()).lower())

    def test_all_success(self):
        self.assertIn("success", _describe(_agg(total=1, success=1)).lower())

    def test_all_failure(self):
        self.assertIn("failed", _describe(_agg(total=1, failure=1)).lower())

    def test_partial(self):
        d = _describe(_agg(total=3, success=2, failure=1))
        self.assertIn("2/3", d)
```

- [ ] **Step 2: Run to verify it fails**

Run: `docker compose exec -T suspicious python manage.py test cortex_job.tests.test_finalise.DescribeTest --keepdb -v1`
Expected: FAIL — `_describe` still expects a dict (`TypeError`/`KeyError`) or the `2/3` assertion fails.

- [ ] **Step 3: Rewrite `_describe` and `finalise`**

In `reconciliation.py`, update imports (add `from cortex_job.cortex_utils.aggregate import aggregate_case, CaseAggregate`) and replace the `finalise` + `_describe` bodies:

```python
def _describe(agg: CaseAggregate) -> str:
    if agg.scored == 0:
        return ("No analyzer was applicable to this submission, so it could "
                "not be analysed. Check that the relevant Cortex analyzers "
                "are enabled.")
    if agg.failure == 0:
        return "All analyzers completed successfully. You can now view the full results."
    if agg.success == 0:
        return "All analyzers failed to run. Please check the configuration and retry."
    return (f"{agg.success}/{agg.scored} analyzers succeeded. "
            "Consider rerunning the rest for a complete analysis.")


def finalise(case) -> None:
    """Compute verdict + side-effects (scoring black box) and set description.

    Does NOT change status/lifecycle_state — the caller owns transitions.
    """
    agg = aggregate_case(case)
    CortexAnalyzerReports.get_report(case)
    case.description = _describe(agg)
    case.save()
```

(If `CortexJobManager` is now unused in `reconciliation.py` at module level EXCEPT in `reconcile_case_core` (`mgr.update_single_job`), keep its import. Remove it only if grep shows no remaining use in the file.)

- [ ] **Step 4: Fix the `FinaliseTest` mocks and run all of `test_finalise`**

In `test_finalise.py`, the finalise test must patch `aggregate_case` OR let it run on a real bare case (all-zero agg). Update the existing finalise test to:

```python
class FinaliseTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="fin_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)

    @patch("cortex_job.cortex_utils.reconciliation.emit_connector_event")  # if referenced; else omit
    @patch("cortex_job.cortex_utils.reconciliation.CortexAnalyzerReports.get_report")
    def test_finalise_runs_scoring_and_sets_description(self, mock_report, *_):
        finalise(self.case)   # real aggregate_case on a bare case -> all zeros
        mock_report.assert_called_once_with(self.case)
        self.assertTrue(self.case.description)
```

Keep `test_finalise_persists_failure_verdict_for_mailless_case` (real get_report) unchanged — it still exercises the full path.

Run: `docker compose exec -T suspicious python manage.py test cortex_job.tests.test_finalise --keepdb -v1`
Expected: PASS (all tests).

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/cortex_job/cortex_utils/reconciliation.py \
        Suspicious/Suspicious/cortex_job/tests/test_finalise.py
git commit -m "refactor(finalise): consume typed CaseAggregate instead of buckets"
```

---

### Task 3: Delete the dead bucket machinery

**Files:**
- Modify: `Suspicious/Suspicious/cortex_job/cortex_utils/cortex_and_job_management.py`
- Modify/Delete: any test that directly tested the deleted methods (e.g. `cortex_job/tests/test_legacy.py` classes exercising `get_results`/`calculate_total_results`, if present).

**Interfaces:**
- Consumes: nothing new. Produces: nothing new (pure deletion).

- [ ] **Step 1: Prove the methods are dead**

Run:
```bash
grep -rnE "\.get_results\(|self\.results|calculate_total_results|update_results\(|\.process_file\(|\.process_mail\(|\.process_mail_archive\(|\.process_mail_artifact\(|\.process_iocs\(" Suspicious/Suspicious --include=*.py | grep -v /tests/
```
Expected: after Task 2, the ONLY hits are inside `cortex_and_job_management.py` itself (the methods calling each other) — zero external callers. If any external caller remains, STOP and report (do not delete).

- [ ] **Step 2: Delete the methods + the `self.results` init**

In `CortexJobManager`, remove the method definitions `get_results`, `process_file`, `process_mail`, `process_mail_archive`, `process_mail_artifact`, `process_iocs`, `update_results`, `calculate_total_results`, and the `self.results = {...}` block (and the now-unused `categories` list) in `__init__`. Do NOT touch `update_single_job`, `get_cortex_jobs_results`, `launch_cortex_jobs`, `manage_ai_jobs`, or the Cortex-API helpers. Remove any imports left unused by the deletion (ruff will flag F401).

- [ ] **Step 3: Remove/adjust tests of deleted methods**

Delete test classes/files that only tested the removed methods (search `cortex_job/tests/` for `get_results`/`calculate_total_results`/`process_iocs` references and remove those tests). Do not touch tests for kept methods.

- [ ] **Step 4: Run the full affected suites — must stay green**

Run:
```bash
docker compose exec -T suspicious python manage.py test cortex_job tasp case_handler score_process --keepdb -v1
```
Expected: OK (0 failures). Then ruff:
```bash
ruff check Suspicious/Suspicious/cortex_job/cortex_utils/cortex_and_job_management.py
```
Expected: All checks passed.

- [ ] **Step 5: Commit**

```bash
git add -u Suspicious/Suspicious/cortex_job/
git commit -m "refactor(cortex): delete dead bucket-aggregation machinery"
```

---

### Task 4: Idempotent KPI counting

**Files:**
- Modify: `Suspicious/Suspicious/case_handler/models.py` (add `kpi_counted`)
- Create: `Suspicious/Suspicious/case_handler/migrations/0017_case_kpi_counted.py`
- Modify: `Suspicious/Suspicious/score_process/scoring/update_handler.py` (`update_kpi_and_user_stats`)
- Test: `Suspicious/Suspicious/score_process/tests/test_kpi_idempotent.py`

**Interfaces:**
- Produces: `Case.kpi_counted: bool` (default False); `update_kpi_and_user_stats(case)` counts at most once per case.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_kpi_idempotent.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from score_process.scoring.update_handler import update_kpi_and_user_stats


class KpiIdempotentTest(TestCase):
    def test_counts_once(self):
        user = get_user_model().objects.create_user(username="kpi_u", password="x")
        case = Case.objects.create(description="", reporter=user, results="Safe")
        update_kpi_and_user_stats(case)
        update_kpi_and_user_stats(case)  # second call must be a no-op
        case.refresh_from_db()
        self.assertTrue(case.kpi_counted)
        # total_cases incremented exactly once across the two calls
        from tasp.cron.kpi import sync_monthly_kpi
        kpi = sync_monthly_kpi()
        self.assertEqual(kpi.total_cases_stats.total_cases, 1)
```

(Ensure `score_process/tests/__init__.py` exists.)

- [ ] **Step 2: Run to verify it fails**

Run: `docker compose exec -T suspicious python manage.py test score_process.tests.test_kpi_idempotent --keepdb -v1`
Expected: FAIL — `Case` has no `kpi_counted` (FieldError) or `total_cases == 2`.

- [ ] **Step 3: Add the field + migration + guard**

Add to `Case` (`case_handler/models.py`, near `finalized_at`):
```python
    kpi_counted = models.BooleanField(default=False, verbose_name="KPI Counted")
```
Generate migration (in container, copy back to host): `manage.py makemigrations case_handler` → `0017_case_kpi_counted.py`.

Rewrite `update_kpi_and_user_stats` (`score_process/scoring/update_handler.py`):
```python
def update_kpi_and_user_stats(case):
    """Update KPI counters and per-user monthly stats — exactly once per case."""
    from django.db import transaction
    try:
        with transaction.atomic():
            locked = Case.objects.select_for_update().get(pk=case.pk)
            if locked.kpi_counted:
                return
            from tasp.cron.kpi import sync_monthly_kpi
            kpi = sync_monthly_kpi()
            kpi.monthly_cases_summary.update_case_results(case.results)
            kpi.monthly_cases_summary.update_case_results(case.category_ai)
            kpi.monthly_cases_summary.save()
            kpi.total_cases_stats.total_cases += 1
            kpi.total_cases_stats.save()

            stats = UserCasesMonthlyStats.objects.filter(
                user=case.reporter, month=kpi.month, year=kpi.year
            ).first()
            if not stats:
                stats = UserCasesMonthlyStats(user=case.reporter, month=kpi.month, year=kpi.year)
            stats.update_case_results(case.results)
            stats.update_case_results(case.category_ai)
            stats.total_cases += 1
            stats.save()

            locked.kpi_counted = True
            locked.save(update_fields=["kpi_counted"])
            case.kpi_counted = True
    except Exception as exc:
        update_cases_logger.error("Failed to update KPI/user stats: %s", exc)
```
(Add `from case_handler.models import Case` at module top if not already imported — check first to avoid a duplicate/circular import; `update_handler.py` already imports Django models, verify.)

- [ ] **Step 4: Run to verify it passes**

Run: `docker compose exec -T suspicious python manage.py test score_process.tests.test_kpi_idempotent --keepdb -v1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/case_handler/models.py \
        Suspicious/Suspicious/case_handler/migrations/0017_case_kpi_counted.py \
        Suspicious/Suspicious/score_process/scoring/update_handler.py \
        Suspicious/Suspicious/score_process/tests/test_kpi_idempotent.py
git commit -m "fix(kpi): count each case at most once via Case.kpi_counted"
```

---

### Task 5: Sane `Result` default (`SUSPICIOUS` → `INCONCLUSIVE`)

**Files:**
- Modify: `Suspicious/Suspicious/case_handler/models.py:50` (`results` default)
- Create: `Suspicious/Suspicious/case_handler/migrations/0018_alter_case_results_default.py`
- Modify: `Suspicious/Suspicious/case_handler/case_utils/case_creator.py` (create path `results="Suspicious"` → `"Inconclusive"`)
- Test: `Suspicious/Suspicious/case_handler/tests/test_result_default.py`

**Interfaces:**
- Produces: new `Case` rows default to `results == "Inconclusive"`.

- [ ] **Step 1: Write the failing test**

```python
# case_handler/tests/test_result_default.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case


class ResultDefaultTest(TestCase):
    def test_new_case_defaults_inconclusive(self):
        user = get_user_model().objects.create_user(username="rd_u", password="x")
        case = Case.objects.create(description="", reporter=user)
        self.assertEqual(case.results, "Inconclusive")
```

- [ ] **Step 2: Run to verify it fails**

Run: `docker compose exec -T suspicious python manage.py test case_handler.tests.test_result_default --keepdb -v1`
Expected: FAIL — `'Suspicious' != 'Inconclusive'`

- [ ] **Step 3: Change the default + migration + creator**

In `case_handler/models.py:50`, change `default=Result.SUSPICIOUS` → `default=Result.INCONCLUSIVE`.
Generate migration (container → copy back): `0018_alter_case_results_default.py` (an `AlterField`; existing rows keep stored values).
In `case_handler/case_utils/case_creator.py`, change the case-construction `results="Suspicious"` → `results="Inconclusive"`. (Leave the allow-listed branch's `"SAFE-ALLOW_LISTED"` and the `results_ai`/`category_ai` defaults untouched.)

- [ ] **Step 4: Run to verify it passes + full sweep**

Run: `docker compose exec -T suspicious python manage.py test case_handler.tests.test_result_default case_handler --keepdb -v1`
Expected: PASS. (No existing test should assert a "Suspicious" default; if one does, it was asserting the fail-dangerous behavior — update it.)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/case_handler/models.py \
        Suspicious/Suspicious/case_handler/migrations/0018_alter_case_results_default.py \
        Suspicious/Suspicious/case_handler/case_utils/case_creator.py \
        Suspicious/Suspicious/case_handler/tests/test_result_default.py
git commit -m "fix(case): default results to Inconclusive, not Suspicious"
```

---

### Task 6: Full-suite + live verification

**Files:** none (verification only)

- [ ] **Step 1: Full affected suite**

Run: `docker compose exec -T suspicious python manage.py test case_handler cortex_job tasp score_process connectors api --keepdb -v1`
Expected: OK (0 failures). And `ruff check Suspicious/` → All checks passed.

- [ ] **Step 2: Rebuild image + recreate both containers + migrate**

```bash
cd deployment
docker compose build suspicious && docker compose up -d --force-recreate suspicious suspicious_celery
docker compose exec -T suspicious python manage.py migrate
```

- [ ] **Step 3: Live spot-check**

Submit a fresh zero-analyzer observable (IP `203.0.113.9`) with a Knox token; poll the case:
```bash
docker compose exec -T suspicious python manage.py shell -c "
from case_handler.models import Case
c=Case.objects.order_by('-id').first()
print(c.id, c.lifecycle_state, c.results, c.kpi_counted, repr(c.description[:60]))"
```
Expected: `FINALIZED Failure True 'No analyzer was applicable...'`. Confirm a brand-new un-finalised case reads `results == "Inconclusive"` (create one without submitting, or check the DB default).

---

## Self-Review

**Spec coverage:**
- CaseAggregate + aggregate_case → Task 1. ✓
- finalise/_describe consume aggregate → Task 2. ✓
- Delete bucket machinery → Task 3. ✓
- Idempotent KPI (kpi_counted) → Task 4. ✓
- Result default Inconclusive → Task 5. ✓
- Verification → Task 6. ✓

**Type consistency:** `CaseAggregate(total, success, failure, deleted, in_progress, waiting)` + `.pending`/`.scored` used identically in Tasks 1, 2. `aggregate_case(case) -> CaseAggregate`, `_describe(agg)`, `Case.kpi_counted` consistent across tasks.

**Placeholder scan:** none — every code step is concrete.

**Open confirmations for the implementer:** exact non-null fields on `Analyzer`/`AnalyzerReport` for Task 1 test fixtures (introspect first); whether `update_handler.py` already imports `Case` (Task 4); migration numbers `0017`/`0018` are the next free integers (verify against the migrations dir before generating).
