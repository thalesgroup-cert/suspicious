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
# Stub out Celery so tasks.py can be imported without a broker
# ---------------------------------------------------------------------------

def _stub_celery():
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


def _stub_cron_modules():
    """
    Pre-stub every tasp.cron.* submodule so that patch() can find them
    without triggering Django model imports (which require DJANGO_SETTINGS_MODULE).
    Each submodule is a MagicMock with the specific function as a real callable.
    """
    cron_pkg = MagicMock()
    sys.modules.setdefault("tasp.cron", cron_pkg)

    # fetch_emails
    fetch_emails_mod = MagicMock()
    fetch_emails_mod.fetch_and_process_emails = MagicMock()
    sys.modules["tasp.cron.fetch_emails"] = fetch_emails_mod
    cron_pkg.fetch_emails = fetch_emails_mod

    # sync_cortex
    sync_cortex_mod = MagicMock()
    sync_cortex_mod.sync_cortex_analyzers = MagicMock()
    sys.modules["tasp.cron.sync_cortex"] = sync_cortex_mod
    cron_pkg.sync_cortex = sync_cortex_mod

    # user_and_cases
    user_and_cases_mod = MagicMock()
    user_and_cases_mod.update_ongoing_case_jobs = MagicMock()
    user_and_cases_mod.sync_user_profiles = MagicMock()
    sys.modules["tasp.cron.user_and_cases"] = user_and_cases_mod
    cron_pkg.user_and_cases = user_and_cases_mod

    # suspicious
    suspicious_mod = MagicMock()
    suspicious_mod.check_challengeable = MagicMock()
    suspicious_mod.remove_old_suspicious_emails = MagicMock()
    sys.modules["tasp.cron.suspicious"] = suspicious_mod
    cron_pkg.suspicious = suspicious_mod

    # kpi
    kpi_mod = MagicMock()
    kpi_mod.sync_monthly_kpi = MagicMock()
    sys.modules["tasp.cron.kpi"] = kpi_mod
    cron_pkg.kpi = kpi_mod

    # cleanup
    cleanup_mod = MagicMock()
    cleanup_mod.delete_old_analyzer_reports = MagicMock()
    sys.modules["tasp.cron.cleanup"] = cleanup_mod
    cron_pkg.cleanup = cleanup_mod

    # watcher
    watcher_mod = MagicMock()
    watcher_mod.run_watcher_sync = MagicMock()
    sys.modules["tasp.cron.watcher"] = watcher_mod
    cron_pkg.watcher = watcher_mod


_stub_celery()
_stub_cron_modules()

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
