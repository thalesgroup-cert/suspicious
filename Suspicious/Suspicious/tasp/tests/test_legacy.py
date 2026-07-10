"""
Unit tests for tasp — retained coverage for unique behaviours not exercised
by the dedicated test modules.

The Celery-wrapper tests (TestFetchEmailsTask … TestWatcherSyncTask) were
removed because the bind=True task proxy is incompatible with the old
direct-call pattern used here, and that coverage is superseded by the
dedicated tasp/tests/test_*.py modules.
"""
import sys
import unittest
from unittest.mock import MagicMock


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
        sys.modules["django"] = MagicMock()
        sys.modules["django.contrib"] = MagicMock()
        sys.modules["django.contrib.admin"] = django_stub
        sys.modules["django_celery_results"] = results_stub
        sys.modules["django_celery_results.models"] = MagicMock(TaskResult=task_result_cls)
        sys.modules["django_celery_results.admin"] = MagicMock(TaskResultAdmin=base_admin_cls)

        sys.modules.pop("tasp.admin", None)
        from tasp.admin import TaskResultAdmin

        admin_instance = TaskResultAdmin.__new__(TaskResultAdmin)
        admin_instance.message_user = MagicMock()

        qs = self._make_queryset(["FAILURE", "SUCCESS", "FAILURE"])
        admin_instance.requeue_failed(MagicMock(), qs)

        self.assertEqual(celery_stub.current_app.send_task.call_count, 2)
        admin_instance.message_user.assert_called_once()
        msg = admin_instance.message_user.call_args[0][1]
        self.assertIn("2", msg)

    def test_skips_non_failure_rows(self):
        celery_stub = MagicMock()
        django_stub = MagicMock()

        sys.modules["celery"] = celery_stub
        sys.modules["django"] = MagicMock()
        sys.modules["django.contrib"] = MagicMock()
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
