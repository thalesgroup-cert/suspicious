# Redis + Celery (R1 + P1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `django-crontab` with Celery + Beat, add two Redis containers (broker and cache), switch sessions to Redis, and cache dashboard summary responses with a 2-minute TTL.

**Architecture:** Thin `@shared_task` wrappers in `tasp/tasks.py` call existing `tasp/cron/*.py` functions unchanged. `django-celery-results` stores task results (including failures) in MariaDB; a Django admin action requeues FAILURE rows. Two Redis containers: `redis_broker` (Celery broker) and `redis_cache` (Django sessions + dashboard cache). Combined `suspicious_celery` container runs worker + Beat.

**Tech Stack:** `celery[redis]~=5.3`, `django-celery-results~=2.5`, Django built-in `RedisCache`, Docker Compose Redis 7 Alpine.

**Spec:** `docs/superpowers/specs/2026-04-17-redis-celery-design.md`

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Modify | `Suspicious/requirements.txt` | Add celery + django-celery-results, remove django_crontab |
| Create | `Suspicious/Suspicious/suspicious/celery.py` | Celery app definition |
| Modify | `Suspicious/Suspicious/suspicious/__init__.py` | Export celery_app so workers auto-discover |
| Modify | `Suspicious/Suspicious/suspicious/settings.py` | CELERY_*, CACHES, SESSION_ENGINE, BEAT_SCHEDULE; remove CRONJOBS |
| Create | `Suspicious/Suspicious/tasp/tasks.py` | Thin @shared_task wrappers over cron functions |
| Modify | `Suspicious/Suspicious/tasp/tests.py` | Unit tests for task wrappers |
| Create | `Suspicious/Suspicious/tasp/admin.py` | Admin requeue action for FAILURE TaskResult rows |
| Modify | `Suspicious/Suspicious/api/views/dashboard.py` | cache.get/set in DashboardSummaryView + two aggregate views |
| Modify | `deployment/compose_databases.yaml` | Add redis_broker + redis_cache base service defs |
| Modify | `deployment/compose_apps.yaml` | Add suspicious_celery def, remove suspicious_cron |
| Modify | `deployment/docker-compose.yml` | Wire Redis + celery services; remove suspicious_cron |
| Modify | `deployment/.env` | Add REDIS_BROKER_VERSION + REDIS_CACHE_VERSION vars |

---

## Task 1: Update Python Dependencies

**Files:**
- Modify: `Suspicious/requirements.txt`

- [ ] **Step 1: Edit requirements.txt**

Open `Suspicious/requirements.txt`. Remove the line:
```
django_crontab
```
Add after the last third-party entry:
```
celery[redis]~=5.3
django-celery-results~=2.5
```

- [ ] **Step 2: Install inside the container or local venv**

```bash
pip install celery[redis]~=5.3 django-celery-results~=2.5
pip uninstall django_crontab -y
```

Expected: no errors. `celery --version` prints `5.3.x`.

- [ ] **Step 3: Commit**

```bash
git add Suspicious/requirements.txt
git commit -m "chore(deps): add celery+redis and django-celery-results; remove django_crontab"
```

---

## Task 2: Celery App Definition

**Files:**
- Create: `Suspicious/Suspicious/suspicious/celery.py`
- Modify: `Suspicious/Suspicious/suspicious/__init__.py`

- [ ] **Step 1: Create `celery.py`**

Create `Suspicious/Suspicious/suspicious/celery.py` with this exact content:

```python
import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "suspicious.settings")

app = Celery("suspicious")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
```

- [ ] **Step 2: Update `__init__.py`**

Replace the contents of `Suspicious/Suspicious/suspicious/__init__.py` with:

```python
from .celery import app as celery_app

__all__ = ("celery_app",)
```

- [ ] **Step 3: Smoke test — import without error**

```bash
cd Suspicious && python -c "import suspicious.celery; print('OK')"
```

Expected output: `OK` (no ImportError). This will fail if `settings.json` is missing — that is expected in a dev environment without the mounted config. The test merely checks the module structure is importable.

- [ ] **Step 4: Commit**

```bash
git add Suspicious/Suspicious/suspicious/celery.py Suspicious/Suspicious/suspicious/__init__.py
git commit -m "feat(celery): add Celery app definition and __init__ export"
```

---

## Task 3: Django Settings — Celery, Cache, Sessions, Beat

**Files:**
- Modify: `Suspicious/Suspicious/suspicious/settings.py`

This task adds six blocks to `settings.py` and removes two old cron blocks. All changes are in the same file.

- [ ] **Step 1: Add Redis config reader (near the top, after other `_config` reads)**

In `settings.py`, after this line:
```python
_email_cfg  = _config.get("email", {})
```
Add:
```python
_redis_cfg  = _config.get("redis", {})
```

- [ ] **Step 2: Add CACHES block (after the Sessions section)**

Find the existing Sessions section:
```python
SESSION_ENGINE               = "django.contrib.sessions.backends.db"
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY      = True     # prevent JS access
SESSION_COOKIE_SAMESITE      = "Lax"   # CSRF protection; Strict breaks OIDC redirects
```

Replace it with:
```python
# ---------------------------------------------------------------------------
# Cache — Redis (redis_cache container)
# ---------------------------------------------------------------------------

_redis_cache_host = _redis_cfg.get("cache_host", "redis_cache")

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": f"redis://{_redis_cache_host}:6379/0",
    }
}

# ---------------------------------------------------------------------------
# Sessions — Redis cache backend (eliminates per-request DB session lookup)
# ---------------------------------------------------------------------------

SESSION_ENGINE               = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS          = "default"
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY      = True     # prevent JS access
SESSION_COOKIE_SAMESITE      = "Lax"   # CSRF protection; Strict breaks OIDC redirects
```

Note: `redis_cache` uses the default Redis port 6379 — no `--port 6380` override needed since each container has its own network namespace.

- [ ] **Step 3: Add Celery config block (after the Sessions/Cache section)**

After the Sessions block, add:
```python
# ---------------------------------------------------------------------------
# Celery — broker (redis_broker container) + result backend (MariaDB)
# ---------------------------------------------------------------------------

from celery.schedules import crontab  # noqa: E402 — after sys.path setup

_redis_broker_host = _redis_cfg.get("broker_host", "redis_broker")

CELERY_BROKER_URL         = f"redis://{_redis_broker_host}:6379/0"
CELERY_RESULT_BACKEND     = "django-db"
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_SERIALIZER    = "json"
CELERY_ACCEPT_CONTENT     = ["json"]

CELERY_BEAT_SCHEDULE = {
    "fetch-emails": {
        "task": "tasp.tasks.fetch_emails",
        "schedule": 60.0,
    },
    "sync-cortex": {
        "task": "tasp.tasks.sync_cortex",
        "schedule": 60.0,
    },
    "update-ongoing-cases": {
        "task": "tasp.tasks.update_ongoing_cases",
        "schedule": 60.0,
    },
    "check-challengeable": {
        "task": "tasp.tasks.check_challengeable",
        "schedule": crontab(hour=0, minute=0),
    },
    "sync-monthly-kpi": {
        "task": "tasp.tasks.sync_monthly_kpi",
        "schedule": 300.0,
    },
    "sync-user-profiles": {
        "task": "tasp.tasks.sync_user_profiles",
        "schedule": 600.0,
    },
    "delete-old-reports": {
        "task": "tasp.tasks.delete_old_reports",
        "schedule": crontab(day_of_month=1, hour=0, minute=0),
    },
    "remove-old-emails": {
        "task": "tasp.tasks.remove_old_emails",
        "schedule": crontab(hour=0, minute=0),
    },
    "watcher-sync": {
        "task": "tasp.tasks.watcher_sync",
        "schedule": 300.0,
    },
}
```

- [ ] **Step 4: Add `django_celery_results` to INSTALLED_APPS, remove `django_crontab`**

Find:
```python
    "django_crontab",
```
Replace with:
```python
    "django_celery_results",
```

- [ ] **Step 5: Remove CRONJOBS block**

Find and delete this entire block:
```python
CRONTAB_LOCK_JOBS = True   # prevent overlapping runs

CRONJOBS = [
    ("*/1 * * * *",  "tasp.cron.fetch_emails.fetch_and_process_emails",       ">> /app/log/fetched_mail.log"),
    ("*/1 * * * *",  "tasp.cron.sync_cortex.sync_cortex_analyzers"),
    ("*/1 * * * *",  "tasp.cron.user_and_cases.update_ongoing_case_jobs",     ">> /app/log/case_updating.log"),
    ("0 0 * * *",    "tasp.cron.suspicious.check_challengeable",              ">> /app/log/case_challengeable.log"),
    ("*/5 * * * *",  "tasp.cron.kpi.sync_monthly_kpi"),
    ("*/10 * * * *", "tasp.cron.user_and_cases.sync_user_profiles"),
    ("0 0 1 * *",    "tasp.cron.cleanup.delete_old_analyzer_reports",         ">> /app/log/cleanup_phishing.log"),
    ("0 0 * * *",    "tasp.cron.suspicious.remove_old_suspicious_emails",     ">> /app/log/cleanup_phishing.log"),
    ("*/5 * * * *",  "tasp.cron.watcher.run_watcher_sync",                   ">> /app/log/watcher_sync.log"),
]
```

Also delete the `# Cron jobs` comment block above it:
```python
# ---------------------------------------------------------------------------
# Cron jobs
# ---------------------------------------------------------------------------
```

- [ ] **Step 6: Commit**

```bash
git add Suspicious/Suspicious/suspicious/settings.py
git commit -m "feat(settings): add Celery/Redis/cache config; replace SESSION_ENGINE; remove CRONJOBS"
```

---

## Task 4: Run django_celery_results Migration

**Prerequisites:** Task 1 (package installed), Task 3 (app in INSTALLED_APPS).

- [ ] **Step 1: Run migrations**

```bash
cd Suspicious && python manage.py migrate django_celery_results
```

Expected output ends with:
```
Running migrations:
  Applying django_celery_results.0001_initial... OK
  ...
```

- [ ] **Step 2: Commit**

```bash
# No new files to commit — migration is in the installed package.
# If manage.py generated a squashed migration in your app, commit that:
git add -p   # review and stage only relevant migration files if any
git commit -m "chore(db): apply django_celery_results migrations" 2>/dev/null || echo "nothing to commit"
```

---

## Task 5: Task Wrappers (TDD)

**Files:**
- Modify: `Suspicious/Suspicious/tasp/tests.py`
- Create: `Suspicious/Suspicious/tasp/tasks.py`

- [ ] **Step 1: Write failing tests**

Replace the contents of `Suspicious/Suspicious/tasp/tests.py` with:

```python
"""
Unit tests for tasp.tasks — thin Celery wrappers over tasp.cron functions.

All Django / Celery infrastructure is stubbed so tests run without a DB
or broker. Each test verifies: (a) the underlying cron function is called,
(b) an exception triggers self.retry() with exponential-backoff countdown.
"""
import sys
import unittest
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Stub out Django + Celery app so tasks.py can be imported without settings
# ---------------------------------------------------------------------------

def _stub_django():
    """Minimal stubs so `from celery import shared_task` works standalone."""
    celery_stub = MagicMock()

    def shared_task_decorator(*args, **kwargs):
        """Return identity decorator — keeps the function callable."""
        def decorator(fn):
            fn.retry = MagicMock(side_effect=Exception("retry"))
            fn.request = MagicMock(retries=0)
            return fn
        if args and callable(args[0]):
            return decorator(args[0])
        return decorator

    celery_stub.shared_task = shared_task_decorator
    celery_stub.utils = MagicMock()
    celery_stub.utils.log = MagicMock()
    celery_stub.utils.log.get_task_logger = MagicMock(return_value=MagicMock())
    sys.modules.setdefault("celery", celery_stub)
    sys.modules.setdefault("celery.utils", celery_stub.utils)
    sys.modules.setdefault("celery.utils.log", celery_stub.utils.log)


_stub_django()

# Clear cached tasks module so our stubs take effect
for _key in list(sys.modules):
    if _key == "tasp.tasks":
        del sys.modules[_key]


def _get_tasks():
    import tasp.tasks as t
    return t


# ---------------------------------------------------------------------------
# Helper: make a bound-task-like callable that exposes .request.retries
# ---------------------------------------------------------------------------

class _BoundTask:
    """Mimics the `self` Celery passes to bind=True tasks."""
    def __init__(self):
        self.request = MagicMock()
        self.request.retries = 0
        self.retry = MagicMock(side_effect=Exception("retry called"))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFetchEmailsTask(unittest.TestCase):
    def test_calls_underlying_function(self):
        t = _get_tasks()
        with patch("tasp.cron.fetch_emails.fetch_and_process_emails") as mock_fn:
            self_ = _BoundTask()
            t.fetch_emails(self_)
            mock_fn.assert_called_once_with()

    def test_retries_on_exception(self):
        t = _get_tasks()
        with patch("tasp.cron.fetch_emails.fetch_and_process_emails", side_effect=RuntimeError("boom")):
            self_ = _BoundTask()
            with self.assertRaises(Exception) as ctx:
                t.fetch_emails(self_)
            self.assertEqual(str(ctx.exception), "retry called")
            self_.retry.assert_called_once()
            _, kwargs = self_.retry.call_args
            self.assertIn("countdown", kwargs)
            self.assertEqual(kwargs["countdown"], 60)  # retries=0 → 60 * 2^0 = 60


class TestSyncCortexTask(unittest.TestCase):
    def test_calls_underlying_function(self):
        t = _get_tasks()
        with patch("tasp.cron.sync_cortex.sync_cortex_analyzers") as mock_fn:
            self_ = _BoundTask()
            t.sync_cortex(self_)
            mock_fn.assert_called_once_with()

    def test_retries_on_exception(self):
        t = _get_tasks()
        with patch("tasp.cron.sync_cortex.sync_cortex_analyzers", side_effect=RuntimeError("boom")):
            self_ = _BoundTask()
            with self.assertRaises(Exception):
                t.sync_cortex(self_)
            self_.retry.assert_called_once()


class TestUpdateOngoingCasesTask(unittest.TestCase):
    def test_calls_underlying_function(self):
        t = _get_tasks()
        with patch("tasp.cron.user_and_cases.update_ongoing_case_jobs") as mock_fn:
            self_ = _BoundTask()
            t.update_ongoing_cases(self_)
            mock_fn.assert_called_once_with()


class TestCheckChallengeableTask(unittest.TestCase):
    def test_calls_underlying_function(self):
        t = _get_tasks()
        with patch("tasp.cron.suspicious.check_challengeable") as mock_fn:
            self_ = _BoundTask()
            t.check_challengeable(self_)
            mock_fn.assert_called_once_with()


class TestSyncMonthlyKpiTask(unittest.TestCase):
    def test_calls_underlying_function(self):
        t = _get_tasks()
        with patch("tasp.cron.kpi.sync_monthly_kpi") as mock_fn:
            self_ = _BoundTask()
            t.sync_monthly_kpi(self_)
            mock_fn.assert_called_once_with()


class TestSyncUserProfilesTask(unittest.TestCase):
    def test_calls_underlying_function(self):
        t = _get_tasks()
        with patch("tasp.cron.user_and_cases.sync_user_profiles") as mock_fn:
            self_ = _BoundTask()
            t.sync_user_profiles(self_)
            mock_fn.assert_called_once_with()


class TestDeleteOldReportsTask(unittest.TestCase):
    def test_calls_underlying_function(self):
        t = _get_tasks()
        with patch("tasp.cron.cleanup.delete_old_analyzer_reports") as mock_fn:
            self_ = _BoundTask()
            t.delete_old_reports(self_)
            mock_fn.assert_called_once_with()


class TestRemoveOldEmailsTask(unittest.TestCase):
    def test_calls_underlying_function(self):
        t = _get_tasks()
        with patch("tasp.cron.suspicious.remove_old_suspicious_emails") as mock_fn:
            self_ = _BoundTask()
            t.remove_old_emails(self_)
            mock_fn.assert_called_once_with()


class TestWatcherSyncTask(unittest.TestCase):
    def test_calls_underlying_function(self):
        t = _get_tasks()
        with patch("tasp.cron.watcher.run_watcher_sync") as mock_fn:
            self_ = _BoundTask()
            t.watcher_sync(self_)
            mock_fn.assert_called_once_with()

    def test_retries_on_exception(self):
        t = _get_tasks()
        with patch("tasp.cron.watcher.run_watcher_sync", side_effect=RuntimeError("timeout")):
            self_ = _BoundTask()
            with self.assertRaises(Exception):
                t.watcher_sync(self_)
            self_.retry.assert_called_once()
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd Suspicious && python -m pytest Suspicious/tasp/tests.py -v 2>/dev/null || \
python manage.py test tasp.tests --verbosity=2
```

Expected: `ImportError: No module named 'tasp.tasks'` or similar — tests fail because `tasp/tasks.py` doesn't exist yet.

- [ ] **Step 3: Create `tasp/tasks.py`**

Create `Suspicious/Suspicious/tasp/tasks.py`:

```python
from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

_RETRY = dict(max_retries=3, acks_late=True)


@shared_task(bind=True, **_RETRY)
def fetch_emails(self):
    from tasp.cron.fetch_emails import fetch_and_process_emails
    try:
        fetch_and_process_emails()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def sync_cortex(self):
    from tasp.cron.sync_cortex import sync_cortex_analyzers
    try:
        sync_cortex_analyzers()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def update_ongoing_cases(self):
    from tasp.cron.user_and_cases import update_ongoing_case_jobs
    try:
        update_ongoing_case_jobs()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def check_challengeable(self):
    from tasp.cron.suspicious import check_challengeable as _check
    try:
        _check()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def sync_monthly_kpi(self):
    from tasp.cron.kpi import sync_monthly_kpi as _sync
    try:
        _sync()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def sync_user_profiles(self):
    from tasp.cron.user_and_cases import sync_user_profiles as _sync
    try:
        _sync()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def delete_old_reports(self):
    from tasp.cron.cleanup import delete_old_analyzer_reports
    try:
        delete_old_analyzer_reports()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def remove_old_emails(self):
    from tasp.cron.suspicious import remove_old_suspicious_emails
    try:
        remove_old_suspicious_emails()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)


@shared_task(bind=True, **_RETRY)
def watcher_sync(self):
    from tasp.cron.watcher import run_watcher_sync
    try:
        run_watcher_sync()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * 2 ** self.request.retries)
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
cd Suspicious && python -m pytest Suspicious/tasp/tests.py -v 2>/dev/null || \
python manage.py test tasp.tests --verbosity=2
```

Expected: all tests PASS (`11 passed` or similar).

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/tasp/tasks.py Suspicious/Suspicious/tasp/tests.py
git commit -m "feat(tasp): add Celery task wrappers for all 9 cron jobs"
```

---

## Task 6: Failed Task Admin (TDD)

**Files:**
- Create: `Suspicious/Suspicious/tasp/admin.py`

There is no dedicated test file for admin — the admin action is tested via a focused unit test added to `tasp/tests.py`.

- [ ] **Step 1: Add failing admin test to `tasp/tests.py`**

Append this class at the end of `Suspicious/Suspicious/tasp/tests.py`:

```python
class TestRequeueFailedAction(unittest.TestCase):
    """Admin action requeues FAILURE TaskResult rows via current_app.send_task."""

    def _make_queryset(self, statuses):
        """Return a fake queryset whose .filter() returns rows with given statuses."""
        rows = []
        for s in statuses:
            row = MagicMock()
            row.status = s
            row.task_name = "tasp.tasks.fetch_emails"
            row.task_args = "[]"
            row.task_kwargs = "{}"
            rows.append(row)

        qs = MagicMock()
        qs.filter.return_value = [r for r in rows if r.status == "FAILURE"]
        return qs

    def test_requeues_only_failure_rows(self):
        celery_stub = MagicMock()
        django_stub = MagicMock()
        results_stub = MagicMock()
        task_result_cls = MagicMock()
        base_admin_cls = MagicMock()

        sys.modules["celery"] = celery_stub
        sys.modules["django.contrib.admin"] = django_stub
        sys.modules["django_celery_results"] = results_stub
        sys.modules["django_celery_results.models"] = MagicMock(TaskResult=task_result_cls)
        sys.modules["django_celery_results.admin"] = MagicMock(TaskResultAdmin=base_admin_cls)

        # Clear cached module
        sys.modules.pop("tasp.admin", None)
        from tasp.admin import TaskResultAdmin

        admin_instance = TaskResultAdmin.__new__(TaskResultAdmin)
        admin_instance.message_user = MagicMock()

        qs = self._make_queryset(["FAILURE", "SUCCESS", "FAILURE"])
        admin_instance.requeue_failed(MagicMock(), qs)

        # send_task called twice (two FAILURE rows), not three
        self.assertEqual(celery_stub.current_app.send_task.call_count, 2)
        admin_instance.message_user.assert_called_once()
        msg = admin_instance.message_user.call_args[0][1]
        self.assertIn("2", msg)

    def test_skips_non_failure_rows(self):
        celery_stub = MagicMock()
        django_stub = MagicMock()

        sys.modules["celery"] = celery_stub
        sys.modules["django.contrib.admin"] = django_stub
        sys.modules["django_celery_results"] = MagicMock()
        sys.modules["django_celery_results.models"] = MagicMock(TaskResult=MagicMock())
        sys.modules["django_celery_results.admin"] = MagicMock(TaskResultAdmin=MagicMock())

        sys.modules.pop("tasp.admin", None)
        from tasp.admin import TaskResultAdmin

        admin_instance = TaskResultAdmin.__new__(TaskResultAdmin)
        admin_instance.message_user = MagicMock()

        qs = self._make_queryset(["SUCCESS", "STARTED"])
        admin_instance.requeue_failed(MagicMock(), qs)

        celery_stub.current_app.send_task.assert_not_called()
```

- [ ] **Step 2: Run tests — verify new tests fail**

```bash
cd Suspicious && python -m pytest Suspicious/tasp/tests.py::TestRequeueFailedAction -v 2>/dev/null || \
python manage.py test tasp.tests.TestRequeueFailedAction --verbosity=2
```

Expected: `ImportError: No module named 'tasp.admin'`.

- [ ] **Step 3: Create `tasp/admin.py`**

Create `Suspicious/Suspicious/tasp/admin.py`:

```python
import json

from celery import current_app
from django.contrib import admin
from django_celery_results.admin import TaskResultAdmin as BaseAdmin
from django_celery_results.models import TaskResult


@admin.register(TaskResult)
class TaskResultAdmin(BaseAdmin):
    actions = ["requeue_failed"]

    @admin.action(description="Requeue selected failed tasks")
    def requeue_failed(self, request, queryset):
        requeued = 0
        for result in queryset.filter(status="FAILURE"):
            try:
                args = json.loads(result.task_args or "[]")
                kwargs = json.loads(result.task_kwargs or "{}")
                current_app.send_task(result.task_name, args=args, kwargs=kwargs)
                requeued += 1
            except Exception:
                pass
        self.message_user(request, f"Requeued {requeued} task(s).")
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
cd Suspicious && python -m pytest Suspicious/tasp/tests.py -v 2>/dev/null || \
python manage.py test tasp.tests --verbosity=2
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/tasp/admin.py Suspicious/Suspicious/tasp/tests.py
git commit -m "feat(tasp): add failed-task admin with requeue action"
```

---

## Task 7: Dashboard Cache (TDD)

**Files:**
- Modify: `Suspicious/Suspicious/api/views/dashboard.py`

- [ ] **Step 1: Write failing tests**

Create `Suspicious/Suspicious/api/tests/test_dashboard_cache.py`. (Create `Suspicious/Suspicious/api/tests/__init__.py` if it doesn't exist.)

```python
"""
Unit tests for DashboardSummaryView caching logic.

Patches django.core.cache.cache so no Redis connection is needed.
"""
import sys
import unittest
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Stub Django internals so views/dashboard.py can be imported standalone
# ---------------------------------------------------------------------------

def _setup_stubs():
    django_stub        = MagicMock()
    drf_stub           = MagicMock()
    conf_stub          = MagicMock()
    conf_stub.settings = MagicMock()
    conf_stub.settings.SUSPICIOUS_EMAIL = None

    sys.modules.setdefault("django",                                  django_stub)
    sys.modules.setdefault("django.conf",                             conf_stub)
    sys.modules.setdefault("django.core",                             MagicMock())
    sys.modules.setdefault("django.core.cache",                       MagicMock())
    sys.modules.setdefault("django.db",                               MagicMock())
    sys.modules.setdefault("django.db.models",                        MagicMock())
    sys.modules.setdefault("django.db.models.functions",              MagicMock())
    sys.modules.setdefault("django_filters",                          MagicMock())
    sys.modules.setdefault("django_filters.rest_framework",           MagicMock())
    sys.modules.setdefault("drf_spectacular",                         MagicMock())
    sys.modules.setdefault("drf_spectacular.utils",                   MagicMock())
    sys.modules.setdefault("rest_framework",                          drf_stub)
    sys.modules.setdefault("rest_framework.generics",                 MagicMock())
    sys.modules.setdefault("rest_framework.permissions",              MagicMock())
    sys.modules.setdefault("rest_framework.response",                 MagicMock())
    sys.modules.setdefault("rest_framework.views",                    MagicMock())
    sys.modules.setdefault("dashboard",                               MagicMock())
    sys.modules.setdefault("dashboard.models",                        MagicMock())
    sys.modules.setdefault("api.serializers",                         MagicMock())
    sys.modules.setdefault("api.serializers.dashboard",               MagicMock())
    sys.modules.setdefault("api.views.filters",                       MagicMock())
    sys.modules.setdefault("api.views.mixins",                        MagicMock())


_setup_stubs()

for _k in list(sys.modules):
    if "api.views.dashboard" in _k:
        del sys.modules[_k]

import django.core.cache as _cache_module  # noqa: E402


class TestDashboardSummaryViewCache(unittest.TestCase):

    def _get_view(self):
        sys.modules.pop("api.views.dashboard", None)
        from api.views.dashboard import DashboardSummaryView
        return DashboardSummaryView

    def test_cache_miss_builds_payload_and_sets_cache(self):
        """On cache miss, _build_summary_payload is called and result is cached."""
        view_cls = self._get_view()
        view = view_cls()
        view.request = MagicMock()
        view.request.user.groups.filter.return_value.exists.return_value = False
        view.request.query_params = {"month": "4", "year": "2026"}

        fake_payload = {"month": 4, "year": 2026, "scope": "ALL", "kpis": {}}

        with patch("django.core.cache.cache") as mock_cache, \
             patch.object(view_cls, "_build_summary_payload", return_value=fake_payload) as mock_build, \
             patch("api.views.dashboard.DashboardSummaryQuerySerializer") as mock_serial, \
             patch("api.views.dashboard.DashboardSummaryResponseSerializer") as mock_resp:

            mock_serial.return_value.is_valid.return_value = True
            mock_serial.return_value.validated_data = {"month": 4, "year": 2026, "scope": "ALL"}
            mock_cache.get.return_value = None  # cache miss

            view.get(view.request)

            mock_cache.get.assert_called_once_with("dashboard:summary:2026:4:ALL")
            mock_build.assert_called_once_with(month=4, year=2026, scope="ALL")
            mock_cache.set.assert_called_once_with(
                "dashboard:summary:2026:4:ALL", fake_payload, 120
            )

    def test_cache_hit_skips_build(self):
        """On cache hit, _build_summary_payload is NOT called."""
        view_cls = self._get_view()
        view = view_cls()
        view.request = MagicMock()
        view.request.user.groups.filter.return_value.exists.return_value = False
        view.request.query_params = {"month": "4", "year": "2026"}

        cached_payload = {"month": 4, "year": 2026, "scope": "ALL", "kpis": {}}

        with patch("django.core.cache.cache") as mock_cache, \
             patch.object(view_cls, "_build_summary_payload") as mock_build, \
             patch("api.views.dashboard.DashboardSummaryQuerySerializer") as mock_serial, \
             patch("api.views.dashboard.DashboardSummaryResponseSerializer"):

            mock_serial.return_value.is_valid.return_value = True
            mock_serial.return_value.validated_data = {"month": 4, "year": 2026, "scope": "ALL"}
            mock_cache.get.return_value = cached_payload  # cache hit

            view.get(view.request)

            mock_build.assert_not_called()
            mock_cache.set.assert_not_called()

    def test_cache_key_includes_scope(self):
        """CISO scope produces a different cache key than ALL scope."""
        view_cls = self._get_view()
        view = view_cls()
        view.request = MagicMock()
        # Simulate CISO user
        view.request.user.groups.filter.return_value.exists.return_value = True
        view.request.query_params = {"month": "4", "year": "2026", "scope": "CISO"}

        with patch("django.core.cache.cache") as mock_cache, \
             patch.object(view_cls, "_build_summary_payload", return_value={}), \
             patch("api.views.dashboard.DashboardSummaryQuerySerializer") as mock_serial, \
             patch("api.views.dashboard.DashboardSummaryResponseSerializer"):

            mock_serial.return_value.is_valid.return_value = True
            mock_serial.return_value.validated_data = {"month": 4, "year": 2026, "scope": "CISO"}
            mock_cache.get.return_value = None

            view.get(view.request)

            key_used = mock_cache.get.call_args[0][0]
            self.assertIn("CISO", key_used)
            self.assertNotIn("ALL", key_used)
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd Suspicious && python -m pytest Suspicious/api/tests/test_dashboard_cache.py -v 2>/dev/null || \
python manage.py test api.tests.test_dashboard_cache --verbosity=2
```

Expected: tests fail because `DashboardSummaryView.get()` has no caching yet.

- [ ] **Step 3: Add caching to `DashboardSummaryView.get()`**

In `Suspicious/Suspicious/api/views/dashboard.py`, add this import at the top (after existing imports):

```python
from django.core.cache import cache
```

Then add the constant after the class opens:

```python
class DashboardSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    DEFAULT_TOP_PREFIXES_LIMIT = 10
    DASHBOARD_CACHE_TTL = 120  # 2 minutes
```

Replace the existing `get()` method body:

```python
    def get(self, request):
        query = DashboardSummaryQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)

        month = query.validated_data["month"]
        year = query.validated_data["year"]
        requested_scope = query.validated_data.get("scope", "ALL")
        scope = self._resolve_scope(requested_scope=requested_scope)

        cache_key = f"dashboard:summary:{year}:{month}:{scope}"
        payload = cache.get(cache_key)
        if payload is None:
            payload = self._build_summary_payload(month=month, year=year, scope=scope)
            cache.set(cache_key, payload, self.DASHBOARD_CACHE_TTL)

        response_serializer = DashboardSummaryResponseSerializer(instance=payload)
        return Response(response_serializer.data)
```

- [ ] **Step 4: Add caching to `MonthlyCasesSummaryAggregateView.get()`**

Find the `MonthlyCasesSummaryAggregateView.get()` method. Replace its body with:

```python
    def get(self, request):
        month, year = self.get_month_year()

        cache_key = f"dashboard:monthly-cases:{year}:{month}"
        data = cache.get(cache_key)
        if data is None:
            data = MonthlyCasesSummary.objects.filter(
                creation_date__month=month,
                creation_date__year=year,
            ).aggregate(
                suspicious_cases=Coalesce(Sum("suspicious_cases"), 0),
                inconclusive_cases=Coalesce(Sum("inconclusive_cases"), 0),
                failure_cases=Coalesce(Sum("failure_cases"), 0),
                dangerous_cases=Coalesce(Sum("dangerous_cases"), 0),
                safe_cases=Coalesce(Sum("safe_cases"), 0),
                challenged_cases=Coalesce(Sum("challenged_cases"), 0),
                allow_listed_cases=Coalesce(Sum("allow_listed_cases"), 0),
                uncategorized_cases=Coalesce(Sum("uncategorized_cases"), 0),
                spam_cases=Coalesce(Sum("spam_cases"), 0),
                newsletter_cases=Coalesce(Sum("newsletter_cases"), 0),
                classic_phishing_cases=Coalesce(Sum("classic_phishing_cases"), 0),
                clone_cases=Coalesce(Sum("clone_cases"), 0),
                blackmail_cases=Coalesce(Sum("blackmail_cases"), 0),
                whaling_cases=Coalesce(Sum("whaling_cases"), 0),
                internal_cases=Coalesce(Sum("internal_cases"), 0),
                external_cases=Coalesce(Sum("external_cases"), 0),
            )
            cache.set(cache_key, data, 120)

        payload = {"month": month, "year": year, **data}
        serializer = MonthlyCasesSummaryAggregateSerializer(instance=payload)
        return Response(serializer.data)
```

- [ ] **Step 5: Add caching to `UserCasesMonthlyStatsAggregateView.get()`**

Find the `UserCasesMonthlyStatsAggregateView.get()` method. Add cache lookup at the start, after `month_str`/`year_str` are set:

```python
    def get(self, request):
        month, year = self.get_month_year()
        month_str = str(month)
        year_str = str(year)

        cache_key = f"dashboard:user-stats:{year}:{month}"
        cached = cache.get(cache_key)
        if cached is not None:
            serializer = UserCasesMonthlyStatsAggregateRowSerializer(instance=cached, many=True)
            return Response(serializer.data)

        rows = (
            UserCasesMonthlyStats.objects.filter(month=month_str, year=year_str)
            .values("user__username")
            .annotate(
                total_cases=Coalesce(Sum("total_cases"), 0),
                total_safe=Coalesce(Sum("safe_cases"), 0),
                total_dangerous=Coalesce(Sum("dangerous_cases"), 0),
                total_suspicious=Coalesce(Sum("suspicious_cases"), 0),
                total_inconclusive=Coalesce(Sum("inconclusive_cases"), 0),
                total_failure=Coalesce(Sum("failure_cases"), 0),
                total_uncategorized=Coalesce(Sum("uncategorized_cases"), 0),
                total_spam=Coalesce(Sum("spam_cases"), 0),
                total_newsletter=Coalesce(Sum("newsletter_cases"), 0),
                total_classic_phishing=Coalesce(Sum("classic_phishing_cases"), 0),
                total_clone=Coalesce(Sum("clone_cases"), 0),
                total_blackmail=Coalesce(Sum("blackmail_cases"), 0),
                total_whaling=Coalesce(Sum("whaling_cases"), 0),
                total_internal=Coalesce(Sum("internal_cases"), 0),
                total_external=Coalesce(Sum("external_cases"), 0),
                total_challenged=Coalesce(Sum("challenged_cases"), 0),
                total_allow_listed=Coalesce(Sum("allow_listed_cases"), 0),
            )
            .order_by("-total_cases", "user__username")
        )

        payload = [
            {
                "username": row["user__username"],
                "month": month,
                "year": year,
                "total_cases": row["total_cases"],
                "total_safe": row["total_safe"],
                "total_dangerous": row["total_dangerous"],
                "total_suspicious": row["total_suspicious"],
                "total_inconclusive": row["total_inconclusive"],
                "total_failure": row["total_failure"],
                "total_uncategorized": row["total_uncategorized"],
                "total_spam": row["total_spam"],
                "total_newsletter": row["total_newsletter"],
                "total_classic_phishing": row["total_classic_phishing"],
                "total_clone": row["total_clone"],
                "total_blackmail": row["total_blackmail"],
                "total_whaling": row["total_whaling"],
                "total_internal": row["total_internal"],
                "total_external": row["total_external"],
                "total_challenged": row["total_challenged"],
                "total_allow_listed": row["total_allow_listed"],
            }
            for row in rows
        ]

        cache.set(cache_key, payload, 120)
        serializer = UserCasesMonthlyStatsAggregateRowSerializer(instance=payload, many=True)
        return Response(serializer.data)
```

- [ ] **Step 6: Run tests — verify they pass**

```bash
cd Suspicious && python -m pytest Suspicious/api/tests/test_dashboard_cache.py -v 2>/dev/null || \
python manage.py test api.tests.test_dashboard_cache --verbosity=2
```

Expected: all 3 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add Suspicious/Suspicious/api/views/dashboard.py \
        Suspicious/Suspicious/api/tests/__init__.py \
        Suspicious/Suspicious/api/tests/test_dashboard_cache.py
git commit -m "feat(dashboard): add 2-min Redis cache to summary and aggregate views"
```

---

## Task 8: Docker Compose — Redis + Celery, Remove Cron

**Files:**
- Modify: `deployment/compose_databases.yaml`
- Modify: `deployment/compose_apps.yaml`
- Modify: `deployment/docker-compose.yml`
- Modify: `deployment/.env`

- [ ] **Step 1: Add Redis base definitions to `compose_databases.yaml`**

In `deployment/compose_databases.yaml`, after the `chromadb:` service block (before the `# Volume stubs` comment), add:

```yaml
  redis_broker:
    init: true
    restart: always
    expose:
      - "6379"
    security_opt:
      - no-new-privileges:true
    networks:
      - suspicious_network

  redis_cache:
    init: true
    restart: always
    expose:
      - "6379"
    security_opt:
      - no-new-privileges:true
    networks:
      - suspicious_network
```

- [ ] **Step 2: Add `suspicious_celery` to `compose_apps.yaml`, remove `suspicious_cron`**

In `deployment/compose_apps.yaml`, find and delete the entire `suspicious_cron:` service block (from `suspicious_cron:` through the closing `networks:` line of that block).

Then add after the `suspicious:` service block:

```yaml
  # ── suspicious_celery (Celery worker + Beat) ──────────────────────────

  suspicious_celery:
    init: true
    restart: always
    command: celery -A suspicious worker --beat --loglevel=info
    volumes:
      - "${CA_PATH}/certfile.pem:/etc/private/certfile.pem:ro"
      - "${CA_PATH}/keyfile.pem:/etc/private/keyfile.pem:ro"
      - "${CA_PATH}/rootcafile.pem:/etc/private/rootcafile.pem:ro"
      - "${SUSPICIOUS_PATH}/logs:/app/log"
      - "${SUSPICIOUS_PATH}/settings.json:/app/settings.json:ro"
    env_file:
      - ".env"
    environment:
      no_proxy: "${NO_PROXY:-},cortex,db_suspicious,rustfs,chromadb,redis_broker,redis_cache"
    healthcheck:
      test: ["CMD-SHELL", "celery -A suspicious inspect ping -d celery@$$HOSTNAME || exit 1"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 30s
    networks:
      - suspicious_network
```

- [ ] **Step 3: Update `docker-compose.yml` — add Redis + Celery services, remove cron**

Find and delete the `suspicious_cron:` service block in `docker-compose.yml`.

After the `chromadb:` service block (before the `# ── Analyzers` comment), add:

```yaml
  redis_broker:
    extends:
      file: compose_databases.yaml
      service: redis_broker
    image: redis:${REDIS_BROKER_VERSION:-7-alpine}
    container_name: redis_broker

  redis_cache:
    extends:
      file: compose_databases.yaml
      service: redis_cache
    image: redis:${REDIS_CACHE_VERSION:-7-alpine}
    container_name: redis_cache
```

After the `suspicious_ui:` service block, add:

```yaml
  suspicious_celery:
    extends:
      file: compose_apps.yaml
      service: suspicious_celery
    image: ghcr.io/thalesgroup-cert/suspicious:${SUSPICIOUS_VERSION:?SUSPICIOUS_VERSION is required}
    container_name: suspicious_celery
    depends_on:
      suspicious:
        condition: service_healthy
      redis_broker:
        condition: service_started
```

- [ ] **Step 4: Add Redis version vars to `.env`**

Append to `deployment/.env`:

```
REDIS_BROKER_VERSION=7-alpine
REDIS_CACHE_VERSION=7-alpine
```

- [ ] **Step 5: Add Redis key to `settings.json`**

In `Suspicious/settings.json` (the mounted config file, not committed — update your local copy and the deployment template), add:

```json
"redis": {
  "broker_host": "redis_broker",
  "cache_host": "redis_cache"
}
```

- [ ] **Step 6: Validate Compose config**

```bash
cd deployment && docker compose config --quiet
```

Expected: no errors printed.

- [ ] **Step 7: Commit**

```bash
git add deployment/compose_databases.yaml \
        deployment/compose_apps.yaml \
        deployment/docker-compose.yml \
        deployment/.env
git commit -m "feat(deploy): add redis_broker + redis_cache + suspicious_celery; remove suspicious_cron"
```

---

## Task 9: Smoke Test End-to-End

- [ ] **Step 1: Start new services**

```bash
cd deployment && docker compose up -d redis_broker redis_cache
```

Expected: both containers start and stay healthy (`docker compose ps` shows `running`).

- [ ] **Step 2: Run migration inside the app container**

```bash
docker exec suspicious python manage.py migrate django_celery_results
```

Expected: migration output ends with `OK`.

- [ ] **Step 3: Start Celery**

```bash
docker compose up -d suspicious_celery
```

Expected: `docker compose logs suspicious_celery` shows:
```
celery@... ready.
beat: Starting...
```

- [ ] **Step 4: Verify tasks appear in Beat**

```bash
docker exec suspicious_celery celery -A suspicious inspect scheduled
```

Expected: lists the 9 scheduled tasks (fetch-emails, sync-cortex, etc.).

- [ ] **Step 5: Stop old cron container**

```bash
docker compose stop suspicious_cron && docker compose rm -f suspicious_cron
```

- [ ] **Step 6: Verify a task executes**

```bash
docker exec suspicious_celery celery -A suspicious call tasp.tasks.sync_cortex
```

Expected: task ID printed, `docker compose logs suspicious_celery` shows the task start and completion.

- [ ] **Step 7: Final commit (if any leftover changes)**

```bash
git status
# Stage and commit any remaining changes
```

---

## Self-Review Checklist

- [x] Redis containers defined in both `compose_databases.yaml` and `docker-compose.yml`
- [x] `suspicious_cron` removed from both `compose_apps.yaml` and `docker-compose.yml`
- [x] All 9 cron jobs mapped 1:1 to Celery tasks
- [x] `django_crontab` removed from INSTALLED_APPS and requirements.txt
- [x] `django_celery_results` added to INSTALLED_APPS
- [x] Session backend changed from `db` to `cache`
- [x] `DashboardSummaryView`, `MonthlyCasesSummaryAggregateView`, `UserCasesMonthlyStatsAggregateView` all cached
- [x] Admin requeue action tested and implemented
- [x] `settings.json` `"redis"` block documented (Task 8 Step 5)
- [x] `celery.py` + `__init__.py` wired so `autodiscover_tasks()` finds `tasp.tasks`
