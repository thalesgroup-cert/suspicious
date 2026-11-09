import threading
from unittest import mock, skipIf

from django.contrib import admin
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction, OperationalError, connection
from django.test import TestCase, TransactionTestCase

from ai_model import registry
from ai_model.models import ModelEvent, ModelVersion
from ai_model.registry import RegistryError
from common.storage.fake import FakeObjectStore

S = ModelVersion.Status
H = "a" * 64


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

    def test_version_zero_status_depends_on_the_slots(self):
        registry.set_active(cand("v1"))
        self.assertEqual(registry.ensure_version_zero().status, S.PREVIOUS)

    def test_version_zero_discarded_stays_a_rollback_target(self):
        registry.set_active(cand("v1"))
        registry.set_active(cand("v2"))  # v1 is previous now
        v0 = registry.ensure_version_zero()
        self.assertEqual(v0.status, S.DISCARDED)
        registry.set_active(v0)
        self.assertEqual(v0.status, S.ACTIVE)
        self.assertEqual(v0.events.count(), 2)  # create_version_zero, set_active

    def test_v0_demoted_then_activated_again(self):
        v0 = registry.ensure_version_zero()
        registry.set_active(cand("v1"))
        registry.set_active(cand("v2"))  # v0 previous -> discarded
        v0.refresh_from_db()
        self.assertEqual(v0.status, S.DISCARDED)
        registry.set_active(v0)

    def test_a_discarded_candidate_still_cannot_be_activated(self):
        d = cand("d1")
        registry.discard(d)
        with self.assertRaises(RegistryError):
            registry.set_active(d)

    def test_one_event_per_version_whose_status_changes(self):
        a, b = cand("v1"), cand("v2")
        registry.set_active(a)
        registry.set_active(b)
        self.assertEqual([x[0] for x in self.events(a)], ["create_candidate", "set_active", "demote"])
        self.assertEqual([x[0] for x in self.events(b)], ["create_candidate", "set_active"])
        registry.set_active(a)  # rollback: a active, b previous
        self.assertEqual([x[0] for x in self.events(a)][-1], "set_active")
        self.assertEqual(a.events.count(), 4)
        self.assertEqual([x[0] for x in self.events(b)][-1], "demote")

    def test_fail_refuses_active_and_previous(self):
        a, b = cand("v1"), cand("v2")
        registry.set_active(a)
        registry.set_active(b)
        for v in (a, b):
            with self.assertRaises(RegistryError):
                registry.fail(v, "x")

    def test_ids_are_validated(self):
        for bad in ("../v9", "a/b", "v 1", "v1.2", "", "x" * 65):
            with self.assertRaises(RegistryError):
                registry.bundle_prefix_for(bad, "j")
            with self.assertRaises(RegistryError):
                registry.bundle_prefix_for("v1", bad)
            with self.assertRaises(RegistryError):
                cand("v1", job_id=bad, bundle_prefix="ai-models/v1/j/")
            with self.assertRaises(RegistryError):
                cand(bad, bundle_prefix="ai-models/v1/j/", job_id="j")

    def test_prefix_must_match_ids(self):
        for bad in ("", "ai-models/other/j-v1/", "ai-models/v1/j-v1/../x/", "ai-models/v1/j-v1"):
            with self.assertRaises(RegistryError):
                cand("v1", bundle_prefix=bad)

    def test_check_constraint_blocks_status_slot_mismatch(self):
        a, b = cand("v1"), cand("v2")
        registry.set_active(a)
        for change in ({"status": S.ACTIVE}, {"active_slot": 2}, {"status": S.ACTIVE, "active_slot": 2}):
            with self.assertRaises(IntegrityError), transaction.atomic():
                ModelVersion.objects.filter(pk=b.pk).update(**change)

    def test_deadlock_is_retried_once_then_mapped(self):
        a = cand("v1")
        real = ModelEvent.objects.create
        calls = []

        def flaky(*args, **kw):
            calls.append(1)
            if len(calls) == 1:
                raise OperationalError(1213, "Deadlock found; secret")
            return real(*args, **kw)

        with mock.patch.object(ModelEvent.objects, "create", side_effect=flaky):
            registry.set_active(a)
        self.assertEqual(a.status, S.ACTIVE)
        b = cand("v2")
        with mock.patch.object(ModelEvent.objects, "create",
                               side_effect=OperationalError(1213, "Deadlock secret")):
            with self.assertRaises(RegistryError) as cm:
                registry.set_active(b)
        self.assertNotIn("secret", str(cm.exception))
        c = cand("v3")
        with mock.patch.object(ModelEvent.objects, "create", side_effect=OperationalError(2006, "gone")):
            with self.assertRaises(OperationalError):
                registry.set_active(c)

    def test_ensure_version_zero_survives_a_lost_race(self):
        real = ModelVersion.objects.create
        v0 = real(version_id="v0", status=S.DISCARDED, trigger="import")
        with mock.patch.object(ModelVersion.objects, "filter", side_effect=[mock.Mock(first=lambda: None),
                                                                            mock.Mock(first=lambda: None),
                                                                            mock.Mock(first=lambda: v0)]), \
                mock.patch.object(ModelVersion.objects, "select_for_update") as sfu:
            sfu.return_value.order_by.return_value.filter.return_value.values_list.return_value = []
            self.assertEqual(registry.ensure_version_zero().pk, v0.pk)

    def test_bundle_prefix(self):
        self.assertEqual(registry.bundle_prefix_for("v2", "job9"), "ai-models/v2/job9/")

    def test_reload_payload(self):
        v0 = registry.ensure_version_zero()
        self.assertEqual(registry.reload_payload(v0), {"active": None, "shadow": None})
        v = cand("v1", manifest_sha256="b" * 64)
        with mock.patch.object(registry, "get_store", return_value=FakeObjectStore()):
            body = registry.reload_payload(v)
        self.assertIsNone(body["shadow"])
        p = body["active"]
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


@skipIf(connection.vendor == "sqlite", "needs row locks and real connections (MariaDB)")
class ConcurrentActivationTest(TransactionTestCase):
    def test_two_threads_leave_exactly_one_active_and_only_registry_errors(self):
        a, b = cand("v1"), cand("v2")
        results = []

        def run(v):
            try:
                registry.set_active(v)
                results.append("ok")
            except Exception as exc:  # record every type
                results.append(type(exc).__name__)
            finally:
                connection.close()

        threads = [threading.Thread(target=run, args=(v,)) for v in (a, b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(ModelVersion.objects.filter(status=S.ACTIVE).count(), 1)
        self.assertTrue(set(results) <= {"ok", "RegistryError"}, results)
        self.assertIn("ok", results)
