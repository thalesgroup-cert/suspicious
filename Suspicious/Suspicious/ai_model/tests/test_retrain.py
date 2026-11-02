"""Plan E, Task 8b: start, poll and register retrain jobs; the schedule and the command."""
from datetime import timedelta
from io import BytesIO, StringIO
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from ai_model import registry, retrain, tasks
from ai_model.models import LabelRecord, ModelVersion, RetrainJob
from ai_model.tests.test_label_sync import CONFIG
from ai_model.tests.test_training_export import full_ledger, make_row
from common.storage.fake import FakeObjectStore
from connectors.contrib.ai_model.client import AiInferenceClient, ServerBusy, TrainJobGone
from connectors.contrib.ai_model.connector import AiModelConnector
from connectors.providers import ProviderUnavailable

S = ModelVersion.Status
J = RetrainJob.State
SHA = "b" * 64
GATE = {"checks": {"accuracy": {"passed": True, "value": 0.86, "threshold": 0.8, "detail": ""}},
        "candidate": {"accuracy": 0.86}, "baseline": {"accuracy": 0.84}, "campaign": {},
        "tier_cutoffs": {"high": 0.9, "medium": 0.6}}


def succeeded(eligible=True, uploaded=registry.BUNDLE_FILE_NAMES, sha=SHA):
    report = dict(GATE, eligible=eligible, manifest_sha256=sha, uploaded=list(uploaded))
    return {"job_id": "x", "state": "succeeded", "progress": 100, "report": report, "error": None}


def view(state, error=None):
    return {"job_id": "x", "state": state, "progress": 10, "report": None, "error": error}


class RetrainBase(TestCase):
    config = CONFIG

    def setUp(self):
        self.store = FakeObjectStore()
        for target, kwargs in (
            (mock.patch.object(registry, "get_store", return_value=self.store), {}),
            (mock.patch("ai_model.ledger.enabled", return_value=True), {}),
            (mock.patch("connectors.registry.registry.instantiate",
                        side_effect=lambda name: AiModelConnector(dict(self.config))), {}),
            (mock.patch.object(tasks.poll_retrain, "apply_async"), {}),
        ):
            target.start()
            self.addCleanup(target.stop)
        self.train = self.client_patch("train", return_value=view("queued"))
        self.status = self.client_patch("train_status", return_value=view("running"))
        self.cancel = self.client_patch("train_cancel", return_value=view("cancelled"))
        full_ledger()

    def client_patch(self, name, **kw):
        patcher = mock.patch.object(AiInferenceClient, name, **kw)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def bundle_keys(self, job):
        bucket, _, prefix = job.prefix.partition("/")
        if not self.store.bucket_exists(bucket):
            return []
        return [o.name for o in self.store.list(bucket, prefix)]

    def upload_some(self, job, names=("heads/safe.npz", "calibration.json")):
        bucket, _, prefix = job.prefix.partition("/")
        for name in names:
            self.store.put(bucket, prefix + name, BytesIO(b"x"))


class StartTest(RetrainBase):
    def test_start_builds_the_train_body_and_records_the_job_first(self):
        seen = {}

        def train(body):
            seen["rows"] = list(RetrainJob.objects.values_list("job_id", "state"))
            seen["body"] = body
            return view("queued")

        self.train.side_effect = train
        job = retrain.start_retrain(user=None)
        body = seen["body"]
        self.assertEqual(seen["rows"], [(job.job_id, J.RUNNING)])  # recorded before the call
        self.assertEqual(set(body), {"job_id", "dataset_url", "bundle_urls", "params"})
        self.assertEqual(body["job_id"], job.job_id)
        self.assertEqual(body["dataset_url"],
                         f"fake://ai-datasets/{job.job_id}/dataset.npz?expires=900")
        self.assertEqual(set(body["bundle_urls"]), set(registry.BUNDLE_FILE_NAMES))
        self.assertTrue(self.store.bucket_exists(registry.BUCKET))
        prefix = registry.bundle_prefix_for(job.target_version, job.job_id)
        self.assertEqual(job.prefix, prefix)
        for name, url in body["bundle_urls"].items():
            self.assertTrue(url.startswith(f"fake://{prefix}{name}?expires="), name)
        params = body["params"]
        self.assertEqual(set(params), {
            "version_id", "seed", "repeats", "baseline", "preprocessing_version", "parent_version",
            "ledger_digest", "campaign_refs_digest", "encoder_id", "encoder_hash", "trainer_revision",
            "campaign_profile"})
        self.assertEqual(params["version_id"], job.target_version)
        self.assertEqual((params["seed"], params["repeats"]), (0, 3))
        self.assertEqual((params["baseline"], params["parent_version"]), ("legacy", "v0"))
        self.assertEqual(params["preprocessing_version"], "chunkmean-tokens-v1")
        self.assertEqual(len(params["ledger_digest"]), 64)
        self.assertEqual(params["campaign_profile"]["distance_threshold"], 0.25)
        tasks.poll_retrain.apply_async.assert_called_once_with((job.job_id,), countdown=30)
        job.refresh_from_db()
        self.assertEqual((job.state, job.rows, job.parent.version_id), (J.RUNNING, 64, "v0"))
        self.assertNotIn("fake://", str(job.params))  # no URL stored

    def test_baseline_is_candidate_for_a_retrained_parent(self):
        v1 = registry.create_candidate("v1", registry.bundle_prefix_for("v1", "j1"), {}, SHA, {},
                                       "manual", None, "j1")
        registry.ensure_version_zero()
        registry.set_active(v1)
        retrain.start_retrain()
        params = self.train.call_args.args[0]["params"]
        self.assertEqual((params["baseline"], params["parent_version"]), ("candidate", "v1"))

    def test_refuses_when_disabled(self):
        with mock.patch("ai_model.ledger.enabled", return_value=False), \
                self.assertRaisesRegex(retrain.RetrainRefused, "disabled"):
            retrain.start_retrain()
        self.assertFalse(RetrainJob.objects.exists())

    def test_refuses_while_a_job_runs(self):
        job = retrain.start_retrain()
        with self.assertRaisesRegex(retrain.RetrainRefused, "running"):
            retrain.start_retrain()
        self.assertEqual(list(RetrainJob.objects.values_list("job_id", flat=True)), [job.job_id])

    def test_the_database_allows_one_running_job(self):
        retrain.start_retrain()
        with self.assertRaises(IntegrityError), transaction.atomic():
            RetrainJob.objects.create(job_id="other", target_version="v9", state=J.RUNNING, running_slot=1,
                                      prefix="p", trigger="manual")

    def test_export_refusal_passes_through_and_records_nothing(self):
        make_row(999, pv="legacy-first128")
        with self.assertRaisesRegex(retrain.RetrainRefused, "ai_model_reembed_ledger"):
            retrain.start_retrain()
        self.assertFalse(RetrainJob.objects.exists())
        self.train.assert_not_called()

    def test_server_409_fails_the_job_and_refuses(self):
        self.train.side_effect = ServerBusy("inference server HTTP 409")
        with self.assertRaisesRegex(retrain.RetrainRefused, "another training job"):
            retrain.start_retrain()
        job = RetrainJob.objects.get()
        self.assertEqual((job.state, job.error, job.running_slot), (J.FAILED, "ServerBusy", None))
        self.assertFalse(self.store.list_buckets() and list(self.store.list(registry.DATASET_BUCKET)))

    def test_a_refused_request_or_rejected_token_fails_at_once(self):
        for exc in (ValueError("inference server refused the request (HTTP 422)"),
                    ProviderUnavailable("token rejected", retryable=False)):
            with self.subTest(exc=type(exc).__name__):
                self.train.side_effect = exc
                with self.assertRaises(retrain.RetrainRefused):
                    retrain.start_retrain()
                self.assertEqual(RetrainJob.objects.latest("pk").state, J.FAILED)

    def test_a_retryable_failure_leaves_the_job_to_the_poll(self):
        self.train.side_effect = ProviderUnavailable("timeout")
        job = retrain.start_retrain()
        self.assertEqual(job.state, J.RUNNING)
        self.status.side_effect = TrainJobGone("inference server HTTP 404")
        self.assertEqual(retrain.poll_once(job.job_id), J.FAILED)


class MutantTest(RetrainBase):
    """Pins behaviour the first suite left open (review of Task 8b)."""

    def test_put_urls_outlive_the_server_wall_limit(self):
        retrain.start_retrain()
        for url in self.train.call_args.args[0]["bundle_urls"].values():
            self.assertTrue(url.endswith("?expires=15300"), url)

    def test_a_lost_slot_race_is_refused_and_drops_the_dataset(self):
        RetrainJob.objects.create(job_id="other", target_version="v9", state=J.RUNNING, running_slot=1,
                                  prefix="p", trigger="manual")
        with mock.patch.object(retrain, "running_job", return_value=None), \
                self.assertRaisesRegex(retrain.RetrainRefused, "another retrain job is running"):
            retrain.start_retrain()
        self.assertEqual(list(self.store.list(registry.DATASET_BUCKET)), [])
        self.train.assert_not_called()

    def test_a_failure_after_the_export_deletes_the_dataset(self):
        from common.storage.base import StoreError
        with mock.patch.object(registry, "ensure_bucket", side_effect=StoreError("unavailable", "down")), \
                self.assertRaisesRegex(retrain.RetrainRefused, "StoreError"):
            retrain.start_retrain()
        self.assertEqual(list(self.store.list(registry.DATASET_BUCKET)), [])
        self.assertFalse(RetrainJob.objects.exists())

    def test_cleanup_ignores_a_tampered_prefix(self):
        self.store.ensure_bucket(registry.BUCKET)
        self.store.put(registry.BUCKET, "v1/j1/manifest.json", BytesIO(b"x"))  # another version's bundle
        job = retrain.start_retrain()
        self.upload_some(job)
        RetrainJob.objects.filter(pk=job.pk).update(prefix="ai-models/")
        self.status.return_value = view("failed")
        retrain.poll_once(job.job_id)
        names = [o.name for o in self.store.list(registry.BUCKET)]
        self.assertEqual(names, ["v1/j1/manifest.json"])  # only this job's own keys went

    def test_eligible_must_be_true_not_truthy(self):
        job = retrain.start_retrain()
        answer = succeeded()
        answer["report"]["eligible"] = "yes"
        self.status.return_value = answer
        retrain.poll_once(job.job_id)
        job.refresh_from_db()
        self.assertIs(job.version.manifest["eligible"], False)

    def test_finish_settles_once_under_a_locking_read(self):
        job = retrain.start_retrain()
        self.upload_some(job, registry.BUNDLE_FILE_NAMES)
        stale = RetrainJob.objects.get(pk=job.pk)
        report = succeeded()["report"]
        with mock.patch.object(RetrainJob.objects, "select_for_update",
                               wraps=RetrainJob.objects.select_for_update) as sfu:
            retrain._finish(stale, J.SUCCEEDED, report=report)
        self.assertTrue(sfu.called)
        retrain._finish(stale, J.SUCCEEDED, report=report)
        retrain._finish(stale, J.FAILED, "Late")
        job.refresh_from_db()
        self.assertEqual((job.state, job.error), (J.SUCCEEDED, ""))
        self.assertEqual(ModelVersion.objects.filter(status=S.CANDIDATE).count(), 1)
        self.assertEqual(len(self.bundle_keys(job)), len(registry.BUNDLE_FILE_NAMES))  # bundle kept

    def test_cancel_of_a_job_the_server_does_not_know_fails_it(self):
        job = retrain.start_retrain()
        self.cancel.side_effect = TrainJobGone("inference server HTTP 404")
        retrain.cancel_retrain()
        job.refresh_from_db()
        self.assertEqual((job.state, job.error), (J.FAILED, "TrainJobGone"))

    def test_poll_error_mapping(self):
        job = retrain.start_retrain()
        self.status.side_effect = ValueError("inference server refused the request (HTTP 400)")
        self.assertEqual(retrain.poll_once(job.job_id), J.RUNNING)
        self.status.side_effect = ProviderUnavailable("token rejected", retryable=False)
        self.assertEqual(retrain.poll_once(job.job_id), J.FAILED)
        job.refresh_from_db()
        self.assertEqual(job.error, "ProviderUnavailable")


class PollTest(RetrainBase):
    def start(self):
        self.job = retrain.start_retrain()
        self.active_before = list(ModelVersion.objects.filter(status=S.ACTIVE).values_list("pk", flat=True))
        return self.job

    def assert_active_unchanged(self):
        self.assertEqual(list(ModelVersion.objects.filter(status=S.ACTIVE).values_list("pk", flat=True)),
                         self.active_before)

    def test_running_requeues(self):
        job = self.start()
        tasks.poll_retrain.apply_async.reset_mock()
        tasks.poll_retrain(job.job_id)
        tasks.poll_retrain.apply_async.assert_called_once_with((job.job_id,), countdown=30)
        self.status.assert_called_once_with(job.job_id)

    def test_a_server_error_requeues(self):
        job = self.start()
        self.status.side_effect = ProviderUnavailable("down")
        self.assertEqual(retrain.poll_once(job.job_id), J.RUNNING)

    def test_succeeded_registers_a_candidate_with_the_report(self):
        job = self.start()
        self.upload_some(job, registry.BUNDLE_FILE_NAMES)
        self.status.return_value = succeeded()
        tasks.poll_retrain.apply_async.reset_mock()
        tasks.poll_retrain(job.job_id)
        tasks.poll_retrain.apply_async.assert_not_called()
        job.refresh_from_db()
        version = job.version
        self.assertEqual((job.state, version.status, version.version_id), (J.SUCCEEDED, S.CANDIDATE, job.target_version))
        self.assertEqual((version.manifest_sha256, version.bundle_prefix, version.job_id),
                         (SHA, job.prefix, job.job_id))
        self.assertEqual(version.parent.version_id, "v0")
        self.assertIs(version.manifest["eligible"], True)
        self.assertEqual(version.manifest["gate"]["checks"], GATE["checks"])
        self.assertEqual(version.manifest["ledger_digest"], job.params["ledger_digest"])
        self.assertEqual(version.campaign_profile["distance_threshold"], 0.25)
        self.assertEqual(list(version.events.values_list("action", flat=True)), ["create_candidate"])
        self.assertEqual(len(self.bundle_keys(job)), len(registry.BUNDLE_FILE_NAMES))  # bundle kept
        self.assertEqual(list(self.store.list(registry.DATASET_BUCKET)), [])  # dataset removed
        self.assert_active_unchanged()

    def test_an_ineligible_candidate_is_registered_and_flagged(self):
        job = self.start()
        self.status.return_value = succeeded(eligible=False)
        retrain.poll_once(job.job_id)
        job.refresh_from_db()
        self.assertEqual(job.version.status, S.CANDIDATE)
        self.assertIs(job.version.manifest["eligible"], False)
        self.assert_active_unchanged()

    def test_a_second_poll_registers_nothing_more(self):
        job = self.start()
        self.status.return_value = succeeded()
        retrain.poll_once(job.job_id)
        self.assertEqual(retrain.poll_once(job.job_id), J.SUCCEEDED)
        self.assertEqual(ModelVersion.objects.filter(status=S.CANDIDATE).count(), 1)

    def check_cleaned(self, job, state, error):
        job.refresh_from_db()
        self.assertEqual((job.state, job.error, job.version, job.running_slot), (state, error, None, None))
        self.assertIsNotNone(job.finished_at)
        self.assertEqual(self.bundle_keys(job), [])
        self.assertEqual(list(self.store.list(registry.DATASET_BUCKET)), [])
        self.assertFalse(ModelVersion.objects.filter(status=S.CANDIDATE).exists())
        self.assert_active_unchanged()

    def test_failed_cancelled_gone_and_half_uploaded_register_nothing_and_clean_up(self):
        cases = (
            (dict(return_value=view("failed", "training: gate: head dangerous")), J.FAILED, "TrainingFailed"),
            (dict(return_value=view("cancelled")), J.CANCELLED, ""),
            (dict(side_effect=TrainJobGone("inference server HTTP 404")), J.FAILED, "TrainJobGone"),
            (dict(return_value=succeeded(uploaded=registry.BUNDLE_FILE_NAMES[:3])), J.FAILED, "IncompleteUpload"),
            (dict(return_value=succeeded(sha="not-a-hash")), J.FAILED, "RegistryError"),
            (dict(return_value={"state": "succeeded", "report": None}), J.FAILED, "TypeError"),
        )
        for kw, state, error in cases:
            with self.subTest(error=error or state):
                job = self.start()
                self.upload_some(job)
                self.status.return_value, self.status.side_effect = kw.get("return_value"), kw.get("side_effect")
                self.assertEqual(retrain.poll_once(job.job_id), state)
                self.check_cleaned(job, state, error)

    def test_the_server_error_text_is_not_stored(self):
        job = self.start()
        self.status.return_value = view("failed", "https://rustfs:9000/x?X-Amz-Signature=abc")
        retrain.poll_once(job.job_id)
        job.refresh_from_db()
        self.assertEqual(job.error, "TrainingFailed")

    def test_six_hours_times_out_and_cancels_on_the_server(self):
        job = self.start()
        RetrainJob.objects.filter(pk=job.pk).update(started_at=timezone.now() - timedelta(hours=6, seconds=1))
        self.assertEqual(retrain.poll_once(job.job_id), J.FAILED)
        self.cancel.assert_called_once_with(job.job_id)
        self.status.assert_called_once_with(job.job_id)  # the server is asked first
        self.check_cleaned(job, J.FAILED, "TimedOut")

    def test_a_job_the_server_finished_is_registered_even_when_polled_late(self):
        job = self.start()
        RetrainJob.objects.filter(pk=job.pk).update(started_at=timezone.now() - timedelta(hours=7))
        self.status.return_value = succeeded()
        self.assertEqual(retrain.poll_once(job.job_id), J.SUCCEEDED)
        self.cancel.assert_not_called()
        self.assert_active_unchanged()

    def test_the_poll_chain_survives_a_missing_token(self):
        job = self.start()
        tasks.poll_retrain.apply_async.reset_mock()
        self.config = dict(CONFIG, token="")
        tasks.poll_retrain(job.job_id)
        tasks.poll_retrain.apply_async.assert_called_once_with((job.job_id,), countdown=30)
        self.assertEqual(RetrainJob.objects.get(pk=job.pk).state, J.RUNNING)

    def test_the_poll_chain_survives_a_database_error_while_settling(self):
        from django.db import DatabaseError
        job = self.start()
        tasks.poll_retrain.apply_async.reset_mock()
        self.status.return_value = view("failed")
        with mock.patch.object(retrain, "_finish", side_effect=DatabaseError("gone")), \
                self.assertRaises(DatabaseError):
            tasks.poll_retrain(job.job_id)
        tasks.poll_retrain.apply_async.assert_called_once_with((job.job_id,), countdown=30)

    def test_the_chain_ends_with_the_job(self):
        job = self.start()
        tasks.poll_retrain.apply_async.reset_mock()
        self.status.return_value = view("cancelled")
        tasks.poll_retrain(job.job_id)
        tasks.poll_retrain.apply_async.assert_not_called()

    def test_the_countdown_outlasts_the_client_timeout(self):
        self.config = dict(CONFIG, timeout_seconds=60)
        job = retrain.start_retrain()
        tasks.poll_retrain.apply_async.assert_called_once_with((job.job_id,), countdown=65)

    def test_a_stale_job_does_not_block_the_next_start(self):
        job = self.start()
        RetrainJob.objects.filter(pk=job.pk).update(started_at=timezone.now() - timedelta(hours=7))
        new = retrain.start_retrain()
        self.assertNotEqual(new.job_id, job.job_id)
        job.refresh_from_db()
        self.assertEqual(job.state, J.FAILED)

    def test_cancel_asks_the_server(self):
        job = self.start()
        self.assertEqual(retrain.cancel_retrain().job_id, job.job_id)
        self.cancel.assert_called_once_with(job.job_id)

    def test_cancel_without_a_job(self):
        self.assertIsNone(retrain.cancel_retrain())


class ScheduleTest(RetrainBase):
    config = dict(CONFIG, retrain_enabled=True)

    def test_does_nothing_unless_enabled(self):
        for config in (CONFIG, dict(CONFIG, retrain_enabled=False)):
            self.config = config
            tasks.maybe_start_retrain()
        self.assertFalse(RetrainJob.objects.exists())
        with mock.patch("ai_model.ledger.enabled", return_value=False):
            self.config = dict(CONFIG, retrain_enabled=True)
            tasks.maybe_start_retrain()
        self.assertFalse(RetrainJob.objects.exists())

    def test_starts_when_the_newest_version_is_older_than_the_interval(self):
        registry.ensure_version_zero()
        ModelVersion.objects.update(created_at=timezone.now() - timedelta(days=31))
        tasks.maybe_start_retrain()
        job = RetrainJob.objects.get()
        self.assertEqual(job.trigger, "schedule")

    def test_waits_while_a_recent_candidate_exists(self):
        registry.ensure_version_zero()
        ModelVersion.objects.update(created_at=timezone.now() - timedelta(days=31))
        registry.create_candidate("v1", registry.bundle_prefix_for("v1", "j1"), {}, SHA, {}, "manual", None, "j1")
        tasks.maybe_start_retrain()
        self.assertFalse(RetrainJob.objects.exists())
        self.config = dict(CONFIG, retrain_enabled=True, retrain_interval_days=0)
        tasks.maybe_start_retrain()
        self.assertTrue(RetrainJob.objects.exists())

    def test_a_running_job_or_a_refused_export_is_quiet(self):
        registry.ensure_version_zero()
        ModelVersion.objects.update(created_at=timezone.now() - timedelta(days=31))
        retrain.start_retrain()
        tasks.maybe_start_retrain()  # running: no exception
        self.assertEqual(RetrainJob.objects.count(), 1)

    def test_a_refused_scheduled_start_backs_off_for_seven_days(self):
        registry.ensure_version_zero()
        ModelVersion.objects.update(created_at=timezone.now() - timedelta(days=31))
        stale = make_row(999, pv="legacy-first128")
        tasks.maybe_start_retrain()
        refused = RetrainJob.objects.get()
        self.assertEqual((refused.state, refused.error, refused.running_slot, refused.trigger),
                         (J.FAILED, "Refused", None, "schedule"))
        LabelRecord.objects.filter(pk=stale.pk).delete()
        tasks.maybe_start_retrain()  # within 7 days: nothing
        self.assertEqual(RetrainJob.objects.count(), 1)
        RetrainJob.objects.update(started_at=timezone.now() - timedelta(days=8))
        tasks.maybe_start_retrain()
        self.assertEqual(RetrainJob.objects.filter(state=J.RUNNING).count(), 1)

    def test_a_failed_scheduled_job_also_backs_off_but_a_manual_one_does_not(self):
        registry.ensure_version_zero()
        ModelVersion.objects.update(created_at=timezone.now() - timedelta(days=31))
        job = retrain.start_retrain()
        self.status.return_value = view("failed")
        retrain.poll_once(job.job_id)
        tasks.maybe_start_retrain()  # the failed job was manual: a scheduled start goes ahead
        self.assertEqual(RetrainJob.objects.filter(state=J.RUNNING, trigger="schedule").count(), 1)
        retrain.poll_once(RetrainJob.objects.get(state=J.RUNNING).job_id)  # fails too
        tasks.maybe_start_retrain()
        self.assertFalse(RetrainJob.objects.filter(state=J.RUNNING).exists())

    def test_a_running_job_writes_no_refused_row(self):
        registry.ensure_version_zero()
        ModelVersion.objects.update(created_at=timezone.now() - timedelta(days=31))
        retrain.start_retrain()
        tasks.maybe_start_retrain()
        self.assertFalse(RetrainJob.objects.filter(error="Refused").exists())


class BeatTest(TestCase):
    def test_the_retrain_check_is_registered_daily(self):
        from suspicious.celery import app
        entry = app.conf.beat_schedule["ai-model-retrain-check"]
        self.assertEqual((entry["task"], entry["schedule"]), ("ai_model.tasks.maybe_start_retrain", 86400.0))


class CommandTest(RetrainBase):
    def run_cmd(self, *args):
        out = StringIO()
        call_command("ai_model_retrain", *args, stdout=out)
        return out.getvalue()

    def test_refuses_when_disabled(self):
        for args in ((), ("--status",), ("--cancel",), ("--wait",)):
            with self.subTest(args=args), mock.patch("ai_model.ledger.enabled", return_value=False), \
                    self.assertRaisesRegex(CommandError, "disabled"):
                self.run_cmd(*args)

    def test_start_prints_the_job_and_no_url_or_token(self):
        out = self.run_cmd()
        job = RetrainJob.objects.get()
        self.assertIn(job.job_id, out)
        self.assertIn("rows 64", out)
        for secret in ("fake://", "expires", CONFIG["token"]):
            self.assertNotIn(secret, out)

    def test_export_refusal_becomes_a_command_error(self):
        make_row(999, pv="legacy-first128")
        with self.assertRaisesRegex(CommandError, "ai_model_reembed_ledger"):
            self.run_cmd()

    def test_status_prints_counts_and_states(self):
        self.run_cmd()
        self.status.return_value = view("failed", "secret text")
        retrain.poll_once(RetrainJob.objects.get().job_id)
        out = self.run_cmd("--status")
        self.assertIn("failed: 1", out)
        self.assertIn("TrainingFailed", out)
        self.assertNotIn("secret text", out)

    def test_status_settles_a_running_job(self):
        self.run_cmd()
        self.status.return_value = view("cancelled")
        self.assertIn("cancelled: 1", self.run_cmd("--status"))

    def test_cancel(self):
        self.assertIn("no retrain job is running", self.run_cmd("--cancel"))
        self.run_cmd()
        self.assertIn("cancel requested", self.run_cmd("--cancel"))
        self.cancel.assert_called_once()

    def test_wait_polls_until_the_job_ends(self):
        self.status.side_effect = [view("running"), succeeded(eligible=False)]
        with mock.patch("ai_model.management.commands.ai_model_retrain.time.sleep") as sleep:
            out = self.run_cmd("--wait")
        self.assertEqual(sleep.call_count, 1)
        self.assertIn("succeeded", out)
        self.assertIn("eligible: no", out)

    def test_wait_gives_up_after_the_timeout(self):
        clock = iter(range(0, 10000, 30))
        with mock.patch("ai_model.management.commands.ai_model_retrain.time.sleep"), \
                mock.patch("ai_model.management.commands.ai_model_retrain.time.monotonic",
                           side_effect=lambda: next(clock)), \
                self.assertRaisesRegex(CommandError, "still running"):
            self.run_cmd("--wait", "--timeout", "60")
        self.assertEqual(RetrainJob.objects.get().state, J.RUNNING)
