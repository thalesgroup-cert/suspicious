from unittest import mock

from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.test import TestCase

from ai_model import registry
from ai_model.models import ModelVersion
from ai_model.registry import RegistryError
from ai_model.tests.test_registry import cand
from common.storage.fake import FakeObjectStore

S = ModelVersion.Status


def eligible(vid, ok=True):
    return cand(vid, manifest={"eligible": ok})


class SetShadowTest(TestCase):
    def setUp(self):
        self.user = User.objects.create(username="u")

    def test_moves_an_eligible_candidate_to_shadow_and_writes_an_event(self):
        v = registry.set_shadow(eligible("v1"), self.user, "try")
        self.assertEqual((v.status, v.shadow_slot), (S.SHADOW, 1))
        self.assertIsNotNone(v.shadow_since)
        self.assertEqual(v.shadow_min_days, 7)
        self.assertEqual(v.recheck, {})
        self.assertEqual(list(v.events.values_list("action", "user_id", "note"))[-1],
                         ("set_shadow", self.user.id, "try"))

    def test_refuses_ineligible_non_candidate_and_second_shadow(self):
        for bad in (eligible("v1", ok=False), cand("v2", manifest={"eligible": "yes"})):
            with self.assertRaises(RegistryError):
                registry.set_shadow(bad, self.user)
        active = registry.set_active(eligible("v3"))
        with self.assertRaises(RegistryError):
            registry.set_shadow(active, self.user)
        registry.set_shadow(eligible("v4"), self.user)
        with self.assertRaises(RegistryError):
            registry.set_shadow(eligible("v5"), self.user)

    def test_check_constraint(self):
        a, b = eligible("v1"), eligible("v2")
        registry.set_shadow(a)
        for change in ({"status": S.SHADOW, "shadow_slot": None}, {"shadow_slot": 1}):
            with self.assertRaises(IntegrityError), transaction.atomic():
                ModelVersion.objects.filter(pk=b.pk).update(**change)
        with self.assertRaises(IntegrityError), transaction.atomic():
            ModelVersion.objects.filter(pk=b.pk).update(status=S.SHADOW, shadow_slot=1)

    def test_discard_and_set_active_free_the_slot(self):
        a = registry.set_shadow(eligible("v1"))
        registry.discard(a)
        self.assertIsNone(a.shadow_slot)
        b = registry.set_shadow(eligible("v2"))
        registry.set_active(b)
        b.refresh_from_db()
        self.assertEqual((b.status, b.shadow_slot), (S.ACTIVE, None))
        registry.set_shadow(eligible("v3"))  # the slot is free again

    def test_reload_payload_presigns_both_and_sends_null_without_shadow(self):
        a, s = eligible("v1"), registry.set_shadow(eligible("v2"))
        with mock.patch.object(registry, "get_store", return_value=FakeObjectStore()):
            both = registry.reload_payload(a, s)
            alone = registry.reload_payload(a, None)
        self.assertEqual(both["shadow"]["version_id"], "v2")
        self.assertEqual(set(both["shadow"]["bundle_urls"]), set(registry.BUNDLE_FILE_NAMES))
        self.assertEqual(both["active"]["version_id"], "v1")
        self.assertIsNone(alone["shadow"])
