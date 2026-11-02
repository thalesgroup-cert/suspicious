import ast
import threading
from pathlib import Path
from unittest import mock, skipIf, skipUnless

from django.contrib import admin
from django.contrib.auth.models import User
from django.db import IntegrityError, connection
from django.test import TestCase, TransactionTestCase

from ai_model import registry
from ai_model.models import ModelEvent, ModelVersion
from ai_model.registry import RegistryError
from common.storage.fake import FakeObjectStore

S = ModelVersion.Status
H = "a" * 64
_P = Path(__file__).resolve().parents
# in the web image /app has no Analyzers/ directory: the drift test then skips
TRAINING = (_P[4] if len(_P) > 4 else Path("/nonexistent")) / "Analyzers/AIMailAnalyzer/training"


def cand(vid, **kw):
    args = dict(version_id=vid, bundle_prefix=registry.bundle_prefix_for(vid, "j-" + vid),
                manifest={}, manifest_sha256=H, campaign_profile={}, trigger="manual",
                user=None, job_id="j-" + vid)
    args.update(kw)
    return registry.create_candidate(**args)


class RegistryTest(TestCase):
    def setUp(self):
        self.user = User.objects.create(username="u")

    def events(self, v):
        return list(v.events.values_list("action", "user_id", "note"))

    def test_create_candidate_writes_row_and_one_event(self):
        v = cand("v1", user=self.user)
        self.assertEqual(v.status, S.CANDIDATE)
        self.assertEqual(self.events(v), [("create_candidate", self.user.id, "")])

    def test_candidate_needs_a_pinned_hash(self):
        for bad in ("", "A" * 64, "a" * 63):
            with self.assertRaises(RegistryError):
                cand("v1", manifest_sha256=bad)

    def test_set_active_keeps_one_previous(self):
        a, b, c = cand("v1"), cand("v2"), cand("v3")
        registry.set_active(a, self.user, "go")
        self.assertEqual(self.events(a)[-1], ("set_active", self.user.id, "go"))
        registry.set_active(b)
        registry.set_active(c)
        for v in (a, b, c):
            v.refresh_from_db()
        self.assertEqual((a.status, b.status, c.status), (S.DISCARDED, S.PREVIOUS, S.ACTIVE))
        self.assertEqual(ModelVersion.objects.filter(status=S.ACTIVE).count(), 1)
        self.assertEqual(ModelVersion.objects.filter(status=S.ACTIVE, active_slot=1).count(), 1)
        self.assertIsNone(b.active_slot)

    def test_rollback_to_previous(self):
        a, b = cand("v1"), cand("v2")
        registry.set_active(a)
        registry.set_active(b)
        registry.set_active(a)
        a.refresh_from_db()
        b.refresh_from_db()
        self.assertEqual((a.status, b.status), (S.ACTIVE, S.PREVIOUS))

    def test_set_active_refuses_other_states(self):
        a = cand("v1")
        registry.set_active(a)
        with self.assertRaises(RegistryError):
            registry.set_active(a)
        d = cand("d1")
        registry.discard(d)
        with self.assertRaises(RegistryError):
            registry.set_active(d)
        f = cand("f1")
        registry.fail(f, "boom")
        with self.assertRaises(RegistryError):
            registry.set_active(f)

    def test_discard_refuses_active_and_writes_one_event(self):
        a, b = cand("v1"), cand("v2")
        registry.set_active(a)
        with self.assertRaises(RegistryError):
            registry.discard(a)
        registry.discard(b, self.user, "no")
        self.assertEqual(self.events(b)[-1], ("discard", self.user.id, "no"))
        self.assertEqual(b.events.count(), 2)
        with self.assertRaises(RegistryError):
            registry.discard(b)

    def test_fail(self):
        a = cand("v1")
        registry.fail(a, "x" * 900)
        self.assertEqual(a.status, S.FAILED)
        self.assertEqual(len(a.events.last().note), 500)
        with self.assertRaises(RegistryError):
            registry.fail(a, "again")
        self.assertEqual(a.events.count(), 2)

    def test_database_refuses_a_second_active_slot(self):
        a, b = cand("v1"), cand("v2")
        registry.set_active(a)
        with self.assertRaises(IntegrityError):
            ModelVersion.objects.filter(pk=b.pk).update(status=S.ACTIVE, active_slot=1)

    def test_version_zero(self):
        v = registry.ensure_version_zero(self.user)
        self.assertEqual((v.version_id, v.status, v.trigger, v.bundle_prefix, v.manifest_sha256),
                         ("v0", S.ACTIVE, "import", "", ""))
        self.assertEqual(v.manifest, registry.V0_MANIFEST)
        self.assertEqual(v.campaign_profile["embedding_version"], "cmp-e1")
        self.assertEqual(registry.ensure_version_zero(self.user).pk, v.pk)
        self.assertEqual(ModelVersion.objects.count(), 1)
        self.assertEqual(ModelEvent.objects.count(), 1)

    def test_version_zero_then_candidate_then_back(self):
        v0 = registry.ensure_version_zero()
        a = cand("v1")
        registry.set_active(a)
        registry.set_active(v0)
        a.refresh_from_db()
        self.assertEqual(a.status, S.PREVIOUS)

    def test_version_zero_is_not_active_when_another_is(self):
        registry.set_active(cand("v1"))
        self.assertEqual(registry.ensure_version_zero().status, S.DISCARDED)

    def test_bundle_prefix(self):
        self.assertEqual(registry.bundle_prefix_for("v2", "job9"), "ai-models/v2/job9/")

    def test_reload_payload(self):
        v0 = registry.ensure_version_zero()
        self.assertEqual(registry.reload_payload(v0), {"active": None})
        v = cand("v1", manifest_sha256="b" * 64)
        with mock.patch.object(registry, "get_store", return_value=FakeObjectStore()):
            p = registry.reload_payload(v)["active"]
        self.assertEqual(p["version_id"], "v1")
        self.assertEqual(p["manifest_sha256"], "b" * 64)
        self.assertEqual(set(p["bundle_urls"]), set(registry.BUNDLE_FILE_NAMES))
        self.assertEqual(p["bundle_urls"]["manifest.json"],
                         "fake://ai-models/v1/j-v1/manifest.json?expires=900")

    def test_admin_is_read_only(self):
        req = mock.Mock()
        for model in (ModelVersion, ModelEvent):
            ma = admin.site._registry[model]
            self.assertFalse(ma.has_add_permission(req))
            self.assertFalse(ma.has_change_permission(req))
            self.assertFalse(ma.has_delete_permission(req))

    @skipUnless((TRAINING / "bundle.py").exists(), "training package not in this image")
    def test_file_names_match_the_training_package(self):
        def literal(path, name):
            for node in ast.parse((TRAINING / path).read_text()).body:
                if isinstance(node, ast.Assign) and node.targets[0].id == name:
                    return node
        heads = ast.literal_eval(literal("recipe.py", "HEADS").value)
        bundle = ast.unparse(literal("bundle.py", "BUNDLE_FILES").value)
        self.assertIn('f"heads/{h}.npz" for h in HEADS', bundle)
        expected = [f"heads/{h}.npz" for h in heads]
        for rel in ("calibration.json", "knn_index.npz", "campaign_profile.json"):
            self.assertIn(f"'{rel}'", bundle)
            expected.append(rel)
        self.assertEqual(sorted(registry.BUNDLE_FILE_NAMES), sorted(expected + ["manifest.json"]))


@skipIf(connection.vendor == "sqlite", "needs row locks and real connections (MariaDB)")
class ConcurrentActivationTest(TransactionTestCase):
    def test_two_threads_leave_exactly_one_active(self):
        a, b = cand("v1"), cand("v2")
        results = []

        def run(v):
            try:
                registry.set_active(v)
                results.append("ok")
            except RegistryError:
                results.append("refused")
            finally:
                connection.close()

        threads = [threading.Thread(target=run, args=(v,)) for v in (a, b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(ModelVersion.objects.filter(status=S.ACTIVE).count(), 1)
        self.assertIn("ok", results)
