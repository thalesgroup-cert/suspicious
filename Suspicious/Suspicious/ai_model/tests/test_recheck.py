"""Plan F, Task 8 (Ruling F11): recheck a shadow version's gate on the current ledger."""
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from io import BytesIO

from django.contrib.auth.models import User
from django.utils import timezone

from ai_model import registry, retrain, tasks
from ai_model.models import ModelVersion, RetrainJob
from ai_model.tests.test_registry import cand
from ai_model.tests.test_retrain import GATE, RetrainBase, view

S = ModelVersion.Status
J = RetrainJob.State
PROFILE = {"embedding_version": "cmp-e1", "metric": "cosine", "distance_threshold": 0.3,
           "min_members": 3, "n_neighbours": 20, "window_days": 15}
MANIFEST = {"eligible": True, "seed": 7, "repeats": 2, "baseline": "candidate",
            "preprocessing_version": "chunkmean-tokens-v1", "parent_version": "v0",
            "encoder_id": retrain.ENCODER_ID, "trainer_revision": "plan-e-candidate-v1",
            "ledger_digest": "0" * 64, "gate": GATE}


def rechecked(version_id, eligible=True):
    report = dict(GATE, eligible=eligible, version_id=version_id, recheck=True)
    return {"job_id": "x", "state": "succeeded", "progress": 100, "report": report, "error": None}


class RecheckTest(RetrainBase):
    def setUp(self):
        super().setUp()
        self.user = User.objects.create(username="admin")
        self.shadow = registry.set_shadow(cand("v1", manifest=MANIFEST, campaign_profile=PROFILE))
        self.events_before = self.shadow.events.count()

    def start(self):
        return retrain.start_recheck(self.shadow, self.user)

    def test_posts_a_recheck_job_with_the_shadow_recipe_and_seed(self):
        job = self.start()
        body = self.train.call_args.args[0]
        self.assertEqual(set(body), {"job_id", "dataset_url", "params"})  # no upload URLs
        self.assertEqual(body["dataset_url"], f"fake://ai-datasets/{job.job_id}/dataset.npz?expires=900")
        p = body["params"]
        self.assertIs(p["recheck"], True)
        self.assertEqual((p["version_id"], p["seed"], p["repeats"], p["baseline"]), ("v1", 7, 2, "candidate"))
        self.assertEqual((p["parent_version"], p["trainer_revision"]), ("v0", "plan-e-candidate-v1"))
        self.assertEqual(p["campaign_profile"], PROFILE)
        self.assertNotEqual(p["ledger_digest"], "0" * 64)  # the current ledger, not the shadow's
        job.refresh_from_db()
        self.assertEqual((job.state, job.running_slot, job.target_version, job.prefix), (J.RUNNING, 1, "v1", ""))
        self.assertEqual((job.trigger, job.requested_by, job.parent), (ModelVersion.Trigger.MANUAL, self.user, self.shadow))
        self.assertEqual(job.rows, 64)
        self.assertFalse(self.store.bucket_exists(registry.BUCKET))  # no bundle prefix, no PUT URL
        tasks.poll_retrain.apply_async.assert_called_once_with((job.job_id,), countdown=30)
        self.assertEqual(list(self.shadow.events.values_list("action", "user", "note"))[-1],
                         ("start_recheck", self.user.pk, job.job_id))

    def test_refuses_a_version_that_is_not_the_shadow(self):
        for version in (cand("v2", manifest=MANIFEST), registry.discard(self.shadow)):
            with self.subTest(status=version.status), \
                    self.assertRaisesRegex(retrain.RetrainRefused, "shadow"):
                retrain.start_recheck(version, self.user)
        self.assertFalse(RetrainJob.objects.exists())
        self.train.assert_not_called()

    def test_refuses_while_a_job_runs(self):
        job = retrain.start_retrain()
        with self.assertRaises(retrain.JobRunning):
            retrain.start_recheck(self.shadow, self.user)
        self.assertEqual(list(RetrainJob.objects.values_list("job_id", flat=True)), [job.job_id])

    def test_a_running_recheck_holds_the_slot(self):
        self.start()
        with self.assertRaises(retrain.JobRunning):
            retrain.start_retrain()

    def test_success_stores_the_result_and_creates_no_candidate(self):
        for eligible in (True, False):
            with self.subTest(eligible=eligible):
                job = self.start()
                self.status.return_value = rechecked("v1", eligible)
                before = timezone.now()
                self.assertEqual(retrain.poll_once(job.job_id), J.SUCCEEDED)
                job.refresh_from_db()
                self.shadow.refresh_from_db()
                self.assertEqual(self.shadow.status, S.SHADOW)
                self.assertIsNone(job.version)
                self.assertEqual(set(self.shadow.recheck), {"job_id", "passed", "finished_at"})
                self.assertEqual(self.shadow.recheck["job_id"], job.job_id)
                self.assertIs(self.shadow.recheck["passed"], eligible)
                at = datetime.fromisoformat(self.shadow.recheck["finished_at"])
                self.assertEqual(at.utcoffset(), timedelta(0))
                self.assertEqual(at, job.finished_at.astimezone(dt_timezone.utc))
                self.assertGreaterEqual(at, before)
                self.assertEqual(ModelVersion.objects.count(), 1)  # no candidate
                self.assertEqual(self.shadow.events.last().action, "recheck")
                self.assertEqual(list(self.store.list(registry.DATASET_BUCKET)), [])

    def test_failed_cancelled_or_malformed_leave_recheck_and_version_unchanged(self):
        self.shadow.recheck = {"job_id": "old", "passed": True, "finished_at": "2026-11-01T00:00:00+00:00"}
        self.shadow.save(update_fields=["recheck"])
        cases = ((view("failed", "training: dataset folders"), J.FAILED),
                 (view("cancelled"), J.CANCELLED),
                 ({"state": "succeeded", "report": None}, J.FAILED),
                 (rechecked("v9"), J.FAILED))  # a report for another version
        for answer, state in cases:
            with self.subTest(answer=answer):
                job = self.start()
                # a file where a training job's cleanup would look: a recheck deletes no bundle file
                bucket, _, key = registry.bundle_prefix_for("v1", job.job_id).partition("/")
                self.store.ensure_bucket(bucket)
                self.store.put(bucket, key + "manifest.json", BytesIO(b"x"))
                self.status.return_value = answer
                self.assertEqual(retrain.poll_once(job.job_id), state)
                self.shadow.refresh_from_db()
                self.assertEqual((self.shadow.status, self.shadow.recheck["job_id"]), (S.SHADOW, "old"))
                self.assertEqual([o.name for o in self.store.list(bucket, key)], [key + "manifest.json"])
                self.assertEqual(ModelVersion.objects.count(), 1)

    def test_a_shadow_discarded_meanwhile_is_not_written(self):
        job = self.start()
        registry.discard(self.shadow)
        self.status.return_value = rechecked("v1")
        self.assertEqual(retrain.poll_once(job.job_id), J.FAILED)
        self.shadow.refresh_from_db()
        self.assertEqual((self.shadow.status, self.shadow.recheck), (S.DISCARDED, {}))

    def test_a_failed_manual_recheck_does_not_start_the_schedule_backoff(self):
        job = self.start()
        self.status.return_value = view("failed", "x")
        retrain.poll_once(job.job_id)
        self.config = dict(self.config, retrain_enabled=True, retrain_interval_days=0)
        self.train.reset_mock()
        ModelVersion.objects.filter(pk=self.shadow.pk).update(created_at=timezone.now() - timedelta(days=1))
        self.assertIsNotNone(retrain.maybe_start())
        self.train.assert_called_once()
