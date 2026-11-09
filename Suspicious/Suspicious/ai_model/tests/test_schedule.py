"""Plan G, Task 1: schedule.next_run and backoff_until."""
from datetime import timedelta
from unittest import mock

from django.utils import timezone

from ai_model import retrain, schedule
from ai_model.models import ModelVersion, RetrainJob
from ai_model.tests.test_registry import cand
from ai_model.tests.test_retrain import RetrainBase

J = RetrainJob.State


class ScheduleTest(RetrainBase):
    config = {**RetrainBase.config, "retrain_enabled": True, "retrain_interval_days": 10}

    def version(self):
        v = cand("s1")
        ModelVersion.objects.filter(pk=v.pk).update(created_at=timezone.now() - timedelta(days=4))
        v.refresh_from_db()
        return v

    def job(self, state=J.FAILED, trigger=ModelVersion.Trigger.SCHEDULE, age_days=1):
        at = timezone.now() - timedelta(days=age_days)
        return RetrainJob.objects.create(
            job_id=f"j{RetrainJob.objects.count()}", target_version="t", state=state,
            running_slot=1 if state == J.RUNNING else None, prefix="p/", trigger=trigger,
            started_at=at, finished_at=None if state == J.RUNNING else at)

    def test_newest_version_plus_interval(self):
        v = self.version()
        self.assertEqual(schedule.next_run(), v.created_at + timedelta(days=10))
        self.assertIsNone(schedule.backoff_until())

    def test_no_versions_is_due_now(self):
        now = timezone.now()
        self.assertEqual(schedule.next_run(now), now)

    def test_none_when_scheduling_off(self):
        self.version()
        with mock.patch.object(self, "config", {**self.config, "retrain_enabled": False}):
            self.assertIsNone(schedule.next_run())

    def test_none_when_connector_disabled(self):
        self.version()
        with mock.patch("ai_model.ledger.enabled", return_value=False):
            self.assertIsNone(schedule.next_run())

    def test_none_while_a_job_runs(self):
        self.version()
        self.job(J.RUNNING, ModelVersion.Trigger.MANUAL)
        self.assertIsNone(schedule.next_run())

    def test_failed_scheduled_job_pushes_to_end_of_backoff(self):
        self.version()
        job = self.job(age_days=1)
        end = job.started_at + retrain.BACKOFF
        self.assertEqual(schedule.backoff_until(), end)
        self.assertEqual(schedule.next_run(), end)

    def test_old_or_manual_failures_do_not_count(self):
        self.version()
        self.job(age_days=8)
        self.job(trigger=ModelVersion.Trigger.MANUAL)
        self.assertIsNone(schedule.backoff_until())
