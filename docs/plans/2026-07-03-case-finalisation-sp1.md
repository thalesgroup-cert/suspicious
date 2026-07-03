# Case Finalisation SP1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the three divergent case-finalise triggers with one idempotent `reconcile_case` Celery entrypoint driven by an explicit `Case.lifecycle_state` machine, fixing the zero-analyzer finalisation gap.

**Architecture:** Add an authoritative `lifecycle_state` field to `Case` with a guarded transition table; a `reconcile_case(case_id)` Celery task syncs the ledger, advances the state, and finalises (scoring kept as a black box) when no analyzer jobs remain pending; the webhook, cron, and dispatch-time paths all just enqueue that task.

**Tech Stack:** Django 5, Celery, MariaDB, Valkey/Redis (per-case lock via Django cache), pytest-style `manage.py test`.

## Global Constraints

- Django display `status` values stay exactly `On Going` / `Done` / `Challenged` (UI/API depend on them). `To Do` is retired.
- No change to `AnalyzerReport`, `CaseAnalyzerJob`, Cortex dispatch, or the HMAC webhook contract.
- Scoring (`calculate_final_scores`, `calculate_result_ranges`) and side-effects (`CortexAnalyzerReports.get_report`) are consumed **as-is** (black box; SP2/SP3 replace them).
- Zero-report cases resolve to verdict `Failure`.
- Tests run in the container: `docker compose exec -T suspicious python manage.py test <path> --keepdb -v1` (run from `deployment/`; copy edited files in with `docker compose cp` when `/app` is not mounted).
- The interim hotfix (edits in `cortex_and_job_management.generate_description`, `score_process/scoring/update_handler.update_case_results`, `case_handler/case_utils/case_handler.dispatch_pending`) is superseded by this plan; Task 6 removes the inline dispatch finalise and Task 8 rewrites the legacy test.

---

### Task 1: Lifecycle state field + choices

**Files:**
- Create: `Suspicious/Suspicious/case_handler/lifecycle.py`
- Modify: `Suspicious/Suspicious/case_handler/models.py` (Case: add `lifecycle_state`, `finalized_at`)
- Create: `Suspicious/Suspicious/case_handler/migrations/0013_case_lifecycle_state.py`
- Test: `Suspicious/Suspicious/case_handler/tests/test_lifecycle_fields.py`

**Interfaces:**
- Produces: `case_handler.lifecycle.LifecycleState` (TextChoices: `CREATED`, `ANALYZING`, `SCORING`, `FINALIZED`, `CONTESTED`), `STATUS_MAP: dict[str, str]`. `Case.lifecycle_state` (str, default `LifecycleState.CREATED`), `Case.finalized_at` (datetime|None).

- [ ] **Step 1: Write the failing test**

```python
# case_handler/tests/test_lifecycle_fields.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState, STATUS_MAP


class LifecycleFieldsTest(TestCase):
    def test_new_case_defaults_to_created(self):
        user = get_user_model().objects.create_user(username="lc_u", password="x")
        case = Case.objects.create(description="", reporter=user)
        self.assertEqual(case.lifecycle_state, LifecycleState.CREATED)
        self.assertIsNone(case.finalized_at)

    def test_status_map_covers_every_state(self):
        for state in LifecycleState.values:
            self.assertIn(state, STATUS_MAP)
        self.assertEqual(STATUS_MAP[LifecycleState.FINALIZED], "Done")
        self.assertEqual(STATUS_MAP[LifecycleState.CONTESTED], "Challenged")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose exec -T suspicious python manage.py test case_handler.tests.test_lifecycle_fields --keepdb -v1`
Expected: FAIL — `ModuleNotFoundError: No module named 'case_handler.lifecycle'`

- [ ] **Step 3: Write minimal implementation**

```python
# case_handler/lifecycle.py
from django.db import models


class LifecycleState(models.TextChoices):
    CREATED   = "CREATED",   "Created"
    ANALYZING = "ANALYZING", "Analyzing"
    SCORING   = "SCORING",   "Scoring"
    FINALIZED = "FINALIZED", "Finalized"
    CONTESTED = "CONTESTED", "Contested"


# lifecycle_state -> analyst-facing Case.status display value
STATUS_MAP = {
    LifecycleState.CREATED:   "On Going",
    LifecycleState.ANALYZING: "On Going",
    LifecycleState.SCORING:   "On Going",
    LifecycleState.FINALIZED: "Done",
    LifecycleState.CONTESTED: "Challenged",
}
```

```python
# case_handler/models.py — add to Case (near status/results fields)
from case_handler.lifecycle import LifecycleState
# ...
    lifecycle_state = models.CharField(
        max_length=20, choices=LifecycleState.choices,
        default=LifecycleState.CREATED, db_index=True,
        verbose_name="Lifecycle State",
    )
    finalized_at = models.DateTimeField(null=True, blank=True, verbose_name="Finalized At")
```

Generate the migration:
Run: `docker compose exec -T suspicious python manage.py makemigrations case_handler`
Expected: creates `0013_case_lifecycle_state.py` adding both fields.

- [ ] **Step 4: Run test to verify it passes**

Run: `docker compose exec -T suspicious python manage.py test case_handler.tests.test_lifecycle_fields --keepdb -v1`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/case_handler/lifecycle.py \
        Suspicious/Suspicious/case_handler/models.py \
        Suspicious/Suspicious/case_handler/migrations/0013_case_lifecycle_state.py \
        Suspicious/Suspicious/case_handler/tests/test_lifecycle_fields.py
git commit -m "feat(case): add lifecycle_state + finalized_at to Case"
```

---

### Task 2: Guarded transition() + status sync

**Files:**
- Modify: `Suspicious/Suspicious/case_handler/lifecycle.py`
- Test: `Suspicious/Suspicious/case_handler/tests/test_transition.py`

**Interfaces:**
- Consumes: `LifecycleState`, `STATUS_MAP` (Task 1).
- Produces: `case_handler.lifecycle.IllegalTransition(Exception)`; `transition(case, to_state: str) -> None` — validates the edge, sets `case.lifecycle_state`, syncs `case.status` from `STATUS_MAP`, stamps `finalized_at` on entering `FINALIZED`, and saves those fields. `LEGAL_TRANSITIONS: dict[str, set[str]]`.

- [ ] **Step 1: Write the failing test**

```python
# case_handler/tests/test_transition.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from case_handler.lifecycle import (
    LifecycleState, transition, IllegalTransition,
)


class TransitionTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="tr_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)

    def test_legal_transition_syncs_status(self):
        transition(self.case, LifecycleState.ANALYZING)
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.ANALYZING)
        self.assertEqual(self.case.status, "On Going")

    def test_finalize_stamps_finalized_at_and_done(self):
        transition(self.case, LifecycleState.SCORING)
        transition(self.case, LifecycleState.FINALIZED)
        self.case.refresh_from_db()
        self.assertEqual(self.case.status, "Done")
        self.assertIsNotNone(self.case.finalized_at)

    def test_illegal_transition_raises(self):
        with self.assertRaises(IllegalTransition):
            transition(self.case, LifecycleState.CONTESTED)  # CREATED->CONTESTED illegal
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose exec -T suspicious python manage.py test case_handler.tests.test_transition --keepdb -v1`
Expected: FAIL — `ImportError: cannot import name 'transition'`

- [ ] **Step 3: Write minimal implementation**

```python
# case_handler/lifecycle.py — append
from django.utils import timezone


class IllegalTransition(Exception):
    """Raised when a case is moved between two states with no legal edge."""


LEGAL_TRANSITIONS = {
    LifecycleState.CREATED:   {LifecycleState.ANALYZING, LifecycleState.SCORING,
                               LifecycleState.FINALIZED},   # FINALIZED = allow-listed shortcut
    LifecycleState.ANALYZING: {LifecycleState.SCORING},
    LifecycleState.SCORING:   {LifecycleState.FINALIZED},
    LifecycleState.FINALIZED: {LifecycleState.CONTESTED},
    LifecycleState.CONTESTED: {LifecycleState.FINALIZED},
}


def transition(case, to_state: str) -> None:
    current = case.lifecycle_state
    if to_state not in LEGAL_TRANSITIONS.get(current, set()):
        raise IllegalTransition(f"{current} -> {to_state} (case {case.id})")
    case.lifecycle_state = to_state
    case.status = STATUS_MAP[to_state]
    fields = ["lifecycle_state", "status"]
    if to_state == LifecycleState.FINALIZED and case.finalized_at is None:
        case.finalized_at = timezone.now()
        fields.append("finalized_at")
    case.save(update_fields=fields)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `docker compose exec -T suspicious python manage.py test case_handler.tests.test_transition --keepdb -v1`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/case_handler/lifecycle.py \
        Suspicious/Suspicious/case_handler/tests/test_transition.py
git commit -m "feat(case): guarded lifecycle transition() with status sync"
```

---

### Task 3: finalise() — verdict + description (scoring black box)

**Files:**
- Create: `Suspicious/Suspicious/cortex_job/cortex_utils/reconciliation.py`
- Test: `Suspicious/Suspicious/cortex_job/tests/test_finalise.py`

**Interfaces:**
- Consumes: `CortexJobManager.get_results` (populates `mgr.results["total"]` buckets of report-id sets), `CortexAnalyzerReports.get_report(case)` (computes verdict + side-effects, saves case), `update_case_results` empty-reports→`Failure` behaviour (already patched).
- Produces: `cortex_job.cortex_utils.reconciliation.finalise(case) -> None` (runs scoring/verdict/side-effects, sets `case.description`; does NOT touch `status`/`lifecycle_state`), and `_describe(results: dict) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# cortex_job/tests/test_finalise.py
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from cortex_job.cortex_utils.reconciliation import finalise, _describe


class DescribeTest(TestCase):
    def _totals(self, **b):
        keys = ("reports", "success", "inprogress", "failure", "waiting", "deleted")
        t = {k: set() for k in keys}
        for name, ids in b.items():
            t[name] = set(ids)
        return {"total": t}

    def test_zero_reports_description_mentions_no_analyzer(self):
        self.assertIn("analyzer", _describe(self._totals()).lower())

    def test_all_success_description(self):
        d = _describe(self._totals(reports=["r1"], success=["r1"]))
        self.assertIn("success", d.lower())


class FinaliseTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="fin_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)

    @patch("cortex_job.cortex_utils.reconciliation.CortexAnalyzerReports.get_report")
    @patch("cortex_job.cortex_utils.reconciliation.CortexJobManager.get_results")
    def test_finalise_runs_scoring_and_sets_description(self, mock_results, mock_report):
        mock_results.return_value = None
        # get_results populates mgr.results; emulate empty buckets
        def _populate(case):
            return None
        mock_results.side_effect = _populate
        finalise(self.case)
        mock_report.assert_called_once_with(self.case)
        self.assertTrue(self.case.description)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose exec -T suspicious python manage.py test cortex_job.tests.test_finalise --keepdb -v1`
Expected: FAIL — `ModuleNotFoundError: No module named 'cortex_job.cortex_utils.reconciliation'`

- [ ] **Step 3: Write minimal implementation**

```python
# cortex_job/cortex_utils/reconciliation.py
import logging

from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def _describe(results: dict) -> str:
    total = results["total"]
    n = len(total["reports"])
    success = len(total["success"])
    failure = len(total["failure"])
    deleted = len(total["deleted"])
    adjusted = n - deleted if n else 0
    if adjusted == 0:
        return (
            "No analyzer was applicable to this submission, so it could not be "
            "analysed. Check that the relevant Cortex analyzers are enabled."
        )
    if failure == 0:
        return "All analyzers completed successfully. You can now view the full results."
    if success == 0:
        return "All analyzers failed to run. Please check the configuration and retry."
    return (
        f"{success}/{adjusted} analyzers succeeded. "
        "Consider rerunning the rest for a complete analysis."
    )


def finalise(case) -> None:
    """Compute verdict + side-effects (scoring black box) and set description.

    Does NOT change status/lifecycle_state — the caller owns transitions.
    """
    mgr = CortexJobManager()
    mgr.get_results(case)               # populates mgr.results buckets
    # Verdict + KPI + connector side-effects. For zero reports this resolves to
    # the Failure verdict via update_case_results (empty-reports branch).
    CortexAnalyzerReports.get_report(case)
    case.description = _describe(mgr.results)
    case.save(update_fields=["description"])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `docker compose exec -T suspicious python manage.py test cortex_job.tests.test_finalise --keepdb -v1`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/cortex_job/cortex_utils/reconciliation.py \
        Suspicious/Suspicious/cortex_job/tests/test_finalise.py
git commit -m "feat(finalise): verdict+description wrapper over scoring black box"
```

---

### Task 4: reconcile_case_core() — the state advance

**Files:**
- Modify: `Suspicious/Suspicious/cortex_job/cortex_utils/reconciliation.py`
- Test: `Suspicious/Suspicious/cortex_job/tests/test_reconcile_core.py`

**Interfaces:**
- Consumes: `finalise` (Task 3), `transition`/`LifecycleState` (Task 2), `CaseAnalyzerJob.PENDING_STATUSES`, `CortexJobManager.update_single_job(caj)`.
- Produces: `reconciliation.reconcile_case_core(case) -> None` — assumes the caller holds the per-case lock; syncs pending jobs, then advances to `ANALYZING` (jobs pending) or `SCORING`→`finalise`→`FINALIZED` (none pending). Idempotent: returns immediately when `lifecycle_state` is terminal.

- [ ] **Step 1: Write the failing test**

```python
# cortex_job/tests/test_reconcile_core.py
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState
from cortex_job.cortex_utils.reconciliation import reconcile_case_core


class ReconcileCoreTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="rc_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)

    @patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_zero_jobs_finalises(self, mock_finalise):
        reconcile_case_core(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.lifecycle_state, LifecycleState.FINALIZED)
        self.assertEqual(self.case.status, "Done")
        mock_finalise.assert_called_once()

    @patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_terminal_case_is_noop(self, mock_finalise):
        self.case.lifecycle_state = LifecycleState.FINALIZED
        self.case.save(update_fields=["lifecycle_state"])
        reconcile_case_core(self.case)
        mock_finalise.assert_not_called()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose exec -T suspicious python manage.py test cortex_job.tests.test_reconcile_core --keepdb -v1`
Expected: FAIL — `ImportError: cannot import name 'reconcile_case_core'`

- [ ] **Step 3: Write minimal implementation**

```python
# cortex_job/cortex_utils/reconciliation.py — append
from case_handler.lifecycle import LifecycleState, transition
from cortex_job.models import CaseAnalyzerJob

_TERMINAL = {LifecycleState.FINALIZED, LifecycleState.CONTESTED}


def reconcile_case_core(case) -> None:
    """Advance one case. Caller MUST hold the per-case lock."""
    if case.lifecycle_state in _TERMINAL:
        return

    mgr = CortexJobManager()
    pending = list(
        CaseAnalyzerJob.objects
        .filter(case=case, status__in=CaseAnalyzerJob.PENDING_STATUSES)
        .select_related("analyzer_report")
    )
    for caj in pending:
        mgr.update_single_job(caj)

    still_pending = CaseAnalyzerJob.objects.filter(
        case=case, status__in=CaseAnalyzerJob.PENDING_STATUSES
    ).exists()

    if still_pending:
        if case.lifecycle_state == LifecycleState.CREATED:
            transition(case, LifecycleState.ANALYZING)
        return

    transition(case, LifecycleState.SCORING)
    finalise(case)
    transition(case, LifecycleState.FINALIZED)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `docker compose exec -T suspicious python manage.py test cortex_job.tests.test_reconcile_core --keepdb -v1`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/cortex_job/cortex_utils/reconciliation.py \
        Suspicious/Suspicious/cortex_job/tests/test_reconcile_core.py
git commit -m "feat(reconcile): reconcile_case_core state advance"
```

---

### Task 5: reconcile_case Celery task (lock + load)

**Files:**
- Modify: `Suspicious/Suspicious/tasp/tasks.py`
- Test: `Suspicious/Suspicious/tasp/tests/test_reconcile_task.py`

**Interfaces:**
- Consumes: `reconcile_case_core` (Task 4), Django `cache` per-case lock pattern `case_update_lock:<id>` (see existing `process_cortex_job`).
- Produces: Celery task `tasp.tasks.reconcile_case(self, case_id: int)` — acquires the lock (skip if held), loads the case, calls `reconcile_case_core`, releases the lock.

- [ ] **Step 1: Write the failing test**

```python
# tasp/tests/test_reconcile_task.py
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from tasp.tasks import reconcile_case


class ReconcileTaskTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="rt_u", password="x")
        self.case = Case.objects.create(description="", reporter=user)

    @patch("tasp.tasks.reconcile_case_core")
    def test_task_invokes_core_with_loaded_case(self, mock_core):
        reconcile_case.run(self.case.id)
        self.assertEqual(mock_core.call_count, 1)
        passed = mock_core.call_args[0][0]
        self.assertEqual(passed.id, self.case.id)

    @patch("tasp.tasks.reconcile_case_core")
    def test_missing_case_is_noop(self, mock_core):
        reconcile_case.run(999999)
        mock_core.assert_not_called()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose exec -T suspicious python manage.py test tasp.tests.test_reconcile_task --keepdb -v1`
Expected: FAIL — `ImportError: cannot import name 'reconcile_case'`

- [ ] **Step 3: Write minimal implementation**

```python
# tasp/tasks.py — add (mirror the lock constants used by process_cortex_job)
from django.core.cache import cache
from case_handler.models import Case
from cortex_job.cortex_utils.reconciliation import reconcile_case_core

CASE_LOCK_TTL = 300  # seconds; matches existing per-case lock


@shared_task(bind=True)
def reconcile_case(self, case_id: int):
    """Single finalise entrypoint: sync ledger + advance the state machine."""
    lock_key = f"case_update_lock:{case_id}"
    if not cache.add(lock_key, 1, timeout=CASE_LOCK_TTL):
        return  # another worker/webhook owns this case; cron will re-pick it
    try:
        case = Case.objects.filter(id=case_id).first()
        if case is None:
            return
        reconcile_case_core(case)
    finally:
        cache.delete(lock_key)
```

(Use the module's existing `shared_task` import; if the file imports `from celery import shared_task` already, do not duplicate it.)

- [ ] **Step 4: Run test to verify it passes**

Run: `docker compose exec -T suspicious python manage.py test tasp.tests.test_reconcile_task --keepdb -v1`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/tasp/tasks.py Suspicious/Suspicious/tasp/tests/test_reconcile_task.py
git commit -m "feat(tasp): reconcile_case Celery task with per-case lock"
```

---

### Task 6: Rewire the three triggers

**Files:**
- Modify: `Suspicious/Suspicious/api/views/cortex_webhook.py` (enqueue `reconcile_case` instead of `process_cortex_job`)
- Modify: `Suspicious/Suspicious/tasp/cron/user_and_cases.py` (`update_ongoing_cases`: scan all non-terminal cases, enqueue `reconcile_case`)
- Modify: `Suspicious/Suspicious/case_handler/case_utils/case_handler.py` (`dispatch_pending`: replace inline finalise with `reconcile_case.delay(case.id)`)
- Test: `Suspicious/Suspicious/tasp/tests/test_cron_enqueues_jobless.py`

**Interfaces:**
- Consumes: `tasp.tasks.reconcile_case` (Task 5), `LifecycleState` terminal set (Task 2).
- Produces: cron `update_ongoing_cases` enqueues `reconcile_case(case_id)` for every case whose `lifecycle_state` is not terminal (jobless cases included).

- [ ] **Step 1: Write the failing test**

```python
# tasp/tests/test_cron_enqueues_jobless.py
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState
from tasp.cron.user_and_cases import update_ongoing_cases


class CronEnqueuesJoblessTest(TestCase):
    def test_jobless_ongoing_case_is_enqueued(self):
        user = get_user_model().objects.create_user(username="cr_u", password="x")
        case = Case.objects.create(
            description="", reporter=user, lifecycle_state=LifecycleState.CREATED,
        )
        with patch("tasp.cron.user_and_cases.reconcile_case.delay") as mock_delay:
            update_ongoing_cases()
        mock_delay.assert_any_call(case.id)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose exec -T suspicious python manage.py test tasp.tests.test_cron_enqueues_jobless --keepdb -v1`
Expected: FAIL — old cron filters to cases with a pending job, so a jobless case is never enqueued (AssertionError).

- [ ] **Step 3: Write minimal implementation**

Replace the body of `update_ongoing_cases` in `tasp/cron/user_and_cases.py` with a non-terminal scan that enqueues the task (drops the inline per-job manage + `Exists(pending_jobs)` filter):

```python
# tasp/cron/user_and_cases.py
from case_handler.lifecycle import LifecycleState
from tasp.tasks import reconcile_case

CRON_BATCH_SIZE = 500  # keep existing value if already defined

def update_ongoing_cases(self=None):
    _TERMINAL = (LifecycleState.FINALIZED, LifecycleState.CONTESTED)
    case_ids = list(
        Case.objects
        .exclude(lifecycle_state__in=_TERMINAL)
        .order_by("creation_date")
        .values_list("id", flat=True)[:CRON_BATCH_SIZE]
    )
    if not case_ids:
        log_cases.info("No ongoing cases found.")
        return
    for cid in case_ids:
        reconcile_case.delay(cid)
```

In `api/views/cortex_webhook.py`, replace the `process_cortex_job.delay(case_id, job_id)` enqueue with:

```python
    from tasp.tasks import reconcile_case
    reconcile_case.delay(case_id)
```

In `case_handler/case_utils/case_handler.py` `dispatch_pending`, replace the interim inline `CortexJobManager().finalise_case(case)` block (added by the hotfix) with:

```python
        from tasp.tasks import reconcile_case
        reconcile_case.delay(case.id)
```

(Enqueue unconditionally after dispatch — reconcile decides ANALYZING vs finalise. Remove the `CaseAnalyzerJob.exists()` inline-finalise guard.)

- [ ] **Step 4: Run test to verify it passes**

Run: `docker compose exec -T suspicious python manage.py test tasp.tests.test_cron_enqueues_jobless --keepdb -v1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/api/views/cortex_webhook.py \
        Suspicious/Suspicious/tasp/cron/user_and_cases.py \
        Suspicious/Suspicious/case_handler/case_utils/case_handler.py \
        Suspicious/Suspicious/tasp/tests/test_cron_enqueues_jobless.py
git commit -m "refactor(finalise): route webhook/cron/dispatch through reconcile_case"
```

---

### Task 7: Backfill migration + heal command

**Files:**
- Create: `Suspicious/Suspicious/case_handler/migrations/0014_backfill_lifecycle_state.py`
- Create: `Suspicious/Suspicious/case_handler/management/commands/heal_orphaned_cases.py`
- Test: `Suspicious/Suspicious/case_handler/tests/test_heal_orphaned.py`

**Interfaces:**
- Consumes: `reconcile_case.delay` (Task 5), `LifecycleState` (Task 2).
- Produces: management command `heal_orphaned_cases` enqueueing `reconcile_case` for every non-terminal case.

- [ ] **Step 1: Write the failing test**

```python
# case_handler/tests/test_heal_orphaned.py
from unittest.mock import patch
from io import StringIO
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState


class HealOrphanedTest(TestCase):
    def test_enqueues_non_terminal_cases_only(self):
        user = get_user_model().objects.create_user(username="hl_u", password="x")
        ongoing = Case.objects.create(description="", reporter=user,
                                      lifecycle_state=LifecycleState.CREATED)
        Case.objects.create(description="", reporter=user,
                            lifecycle_state=LifecycleState.FINALIZED)
        with patch("case_handler.management.commands.heal_orphaned_cases."
                   "reconcile_case.delay") as mock_delay:
            call_command("heal_orphaned_cases", stdout=StringIO())
        mock_delay.assert_called_once_with(ongoing.id)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker compose exec -T suspicious python manage.py test case_handler.tests.test_heal_orphaned --keepdb -v1`
Expected: FAIL — `CommandError: Unknown command: 'heal_orphaned_cases'`

- [ ] **Step 3: Write minimal implementation**

```python
# case_handler/management/commands/heal_orphaned_cases.py
from django.core.management.base import BaseCommand
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState
from tasp.tasks import reconcile_case


class Command(BaseCommand):
    help = "Enqueue reconcile_case for every non-terminal case."

    def handle(self, *args, **options):
        terminal = (LifecycleState.FINALIZED, LifecycleState.CONTESTED)
        ids = (
            Case.objects.exclude(lifecycle_state__in=terminal)
            .values_list("id", flat=True)
        )
        count = 0
        for cid in ids:
            reconcile_case.delay(cid)
            count += 1
        self.stdout.write(self.style.SUCCESS(f"Enqueued {count} case(s)."))
```

```python
# case_handler/migrations/0014_backfill_lifecycle_state.py
from django.db import migrations


def backfill(apps, schema_editor):
    Case = apps.get_model("case_handler", "Case")
    CaseAnalyzerJob = apps.get_model("cortex_job", "CaseAnalyzerJob")
    PENDING = ("Waiting", "InProgress")  # mirror CaseAnalyzerJob.PENDING_STATUSES
    for case in Case.objects.all().iterator(chunk_size=200):
        if case.status == "Done":
            case.lifecycle_state = "FINALIZED"
            case.finalized_at = case.finalized_at or case.last_update
        elif case.status == "Challenged":
            case.lifecycle_state = "CONTESTED"
        else:  # On Going / To Do
            has_pending = CaseAnalyzerJob.objects.filter(
                case=case, status__in=PENDING
            ).exists()
            case.lifecycle_state = "ANALYZING" if has_pending else "CREATED"
        case.save(update_fields=["lifecycle_state", "finalized_at"])


class Migration(migrations.Migration):
    dependencies = [
        ("case_handler", "0013_case_lifecycle_state"),
        ("cortex_job", "0010_backfill_caseanalyzerjob"),
    ]
    operations = [migrations.RunPython(backfill, migrations.RunPython.noop)]
```

(Confirm `CaseAnalyzerJob.PENDING_STATUSES` exact string values before finalising the migration constant.)

- [ ] **Step 4: Run test to verify it passes**

Run: `docker compose exec -T suspicious python manage.py test case_handler.tests.test_heal_orphaned --keepdb -v1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/case_handler/migrations/0014_backfill_lifecycle_state.py \
        Suspicious/Suspicious/case_handler/management/commands/heal_orphaned_cases.py \
        Suspicious/Suspicious/case_handler/tests/test_heal_orphaned.py
git commit -m "feat(case): backfill lifecycle_state + heal_orphaned_cases command"
```

---

### Task 8: Retire dead code + reconcile legacy tests

**Files:**
- Modify: `Suspicious/Suspicious/cortex_job/cortex_utils/cortex_and_job_management.py` (drop the now-unused status-setting in `generate_description`, or delete `generate_description`/`finalise_case`/`manage_jobs` if no longer referenced)
- Modify: `Suspicious/Suspicious/cortex_job/tests/test_legacy.py` (rewrite `test_empty_results_keep_case_ongoing`)
- Modify: `Suspicious/Suspicious/tasp/tasks.py` (remove `process_cortex_job` if fully replaced)
- Test: existing suites

**Interfaces:**
- Consumes: everything from Tasks 1-7.

- [ ] **Step 1: Update the legacy test to the new behaviour**

```python
# cortex_job/tests/test_legacy.py — replace test_empty_results_keep_case_ongoing
    def test_empty_results_marks_case_done(self):
        # A case with zero analyzer reports is terminal — nothing to wait for.
        from cortex_job.cortex_utils.reconciliation import reconcile_case_core
        from case_handler.lifecycle import LifecycleState
        reconcile_case_core(self.real_case)   # use a real persisted Case, not a Mock
        self.real_case.refresh_from_db()
        self.assertEqual(self.real_case.lifecycle_state, LifecycleState.FINALIZED)
```

(The old test used a `MagicMock(spec=Case)`; the new assertion needs a persisted `Case` — add one in `setUp` as `self.real_case`.)

- [ ] **Step 2: Grep for dead references, run the full affected suites**

Run:
```bash
grep -rn "process_cortex_job\|finalise_case\|manage_jobs\|generate_description" Suspicious/Suspicious --include=*.py | grep -v test
docker compose exec -T suspicious python manage.py test case_handler cortex_job tasp score_process --keepdb -v1
```
Expected: no live references to removed symbols; suites GREEN. Triage the 2 pre-existing `Mock object is not iterable` errors seen earlier — confirm they predate this branch (`git stash` + run) or fix if introduced here.

- [ ] **Step 3: Remove dead code**

Delete `process_cortex_job`, `_case_has_pending_jobs` (if unused), and the status branch of `generate_description` / `finalise_case` / `manage_jobs` that no code path calls anymore. Keep `get_results`, `update_single_job`, `get_report` (still used).

- [ ] **Step 4: Re-run suites**

Run: `docker compose exec -T suspicious python manage.py test case_handler cortex_job tasp score_process --keepdb -v1`
Expected: GREEN.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(finalise): retire process_cortex_job + legacy status paths"
```

---

### Task 9: End-to-end verification on the live stack

**Files:** none (verification only)

- [ ] **Step 1: Rebuild/restart backend + celery with the new code**

Run (from `deployment/`):
```bash
docker compose build suspicious && docker compose up -d suspicious suspicious_celery
docker compose exec -T suspicious python manage.py migrate
docker compose exec -T suspicious python manage.py heal_orphaned_cases
```

- [ ] **Step 2: Submit a zero-analyzer observable and a hash, verify outcomes**

Submit a URL/IP (no matching analyzer) and a hash (CIRCLHashlookup) via `/api/submit/*` with a Knox token. Then:
```bash
docker compose exec -T suspicious python manage.py shell -c "
from case_handler.models import Case
for c in Case.objects.order_by('-id')[:3]:
    print(c.id, c.lifecycle_state, c.status, c.results)
"
```
Expected: zero-analyzer cases → `FINALIZED / Done / Failure`; hash case → `ANALYZING / On Going` then `FINALIZED` after the job resolves (or the stale sweep).

- [ ] **Step 3: Confirm previously-stuck cases healed**

Expected: cases 7 and 8 (from earlier testing) now show `FINALIZED / Done / Failure`.

- [ ] **Step 4: Commit any doc updates** (CLAUDE.md analysis-flow note if wording changed).

---

## Self-Review

**Spec coverage:**
- State model + display mapping → Task 1. ✓
- Transition guard → Task 2. ✓
- reconcile_case entrypoint → Tasks 4-5. ✓
- Trigger unification (webhook/cron/dispatch) → Task 6. ✓
- Finalisation-once + Failure verdict → Tasks 3-4 (+ existing hotfix in update_case_results). ✓
- Data migration + heal command → Task 7. ✓
- Error handling (lock skip, per-case isolation, stale sweep) → Task 5 + unchanged fail_stale_jobs. ✓
- Testing strategy incl. legacy-test rewrite → Tasks 1-8. ✓

**Type consistency:** `LifecycleState`, `STATUS_MAP`, `transition`, `IllegalTransition`, `finalise`, `_describe`, `reconcile_case_core`, `reconcile_case` used with the same signatures across tasks. ✓

**Deferred (not gaps):** typed aggregation, generate_description split, KPI double-count fix (SP2); scoring redesign (SP3).

**Open confirmations for the implementer:** exact `CaseAnalyzerJob.PENDING_STATUSES` string values (Tasks 4/7); whether `generate_description`/`finalise_case`/`manage_jobs` have remaining callers before deletion (Task 8); allow-listed case path (`case_creator.py:60`) should call `transition(case, FINALIZED)` — verify and wire in Task 6 if it currently sets `status="Done"` directly.
