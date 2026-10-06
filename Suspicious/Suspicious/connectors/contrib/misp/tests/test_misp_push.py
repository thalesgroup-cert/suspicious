from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, TestCase

from connectors.contrib.misp.connector import MISPConnector
from connectors.contrib.misp.events import MISPEventManager
from connectors.contrib.misp.objects import build_hash_object
from connectors.contrib.misp.service import MISPService


def _manager(search_result, created=None):
    misp = MagicMock()
    misp.search.return_value = search_result
    misp.get_event.return_value = {"Event": {"id": "7", "info": "x", "date": "2026-10-06"}}
    misp.add_event.return_value = created or {"Event": {"id": "9", "info": "x", "date": "2026-10-06"}}
    return MISPEventManager(SimpleNamespace(misp=misp)), misp


class EventManagerTest(SimpleTestCase):
    def test_existing_event_is_found_by_eventinfo_and_returned(self):
        name = "Email Analysis - Case 5"
        mgr, misp = _manager([{"Event": {"id": "7", "info": name}}])
        with patch("connectors.contrib.misp.events.add_case_number_attribute"):
            event = mgr.get_or_create_event(SimpleNamespace(id=5, results="Dangerous"))
        self.assertEqual(misp.search.call_args.kwargs["eventinfo"], name)
        misp.add_event.assert_not_called()
        self.assertEqual(str(event.id), "7")
        self.assertIn("level::DANGEROUS", [t.name for t in event.tags])

    def test_new_event_is_created_and_returned(self):
        mgr, misp = _manager([])
        with patch("connectors.contrib.misp.events.add_case_number_attribute"):
            event = mgr.get_or_create_event(SimpleNamespace(id=5, results="Suspicious"))
        misp.add_event.assert_called_once()
        self.assertEqual(str(event.id), "9")
        self.assertIn("level::SUSPICIOUS", [t.name for t in event.tags])


class HashObjectTest(SimpleTestCase):
    def test_hashtype_spellings_in_use_are_accepted(self):
        for spelling, relation in (("sha256 hash", "sha256"), ("SHA-256", "sha256"), ("md5", "md5")):
            obj = build_hash_object(SimpleNamespace(hashtype=spelling, value="ab" * 16), 1, "Safe")
            self.assertIsNotNone(obj, spelling)
            self.assertEqual(obj.attributes[0].object_relation, relation)

    def test_unsupported_hashtype_is_skipped(self):
        self.assertIsNone(build_hash_object(SimpleNamespace(hashtype="ssdeep", value="x"), 1, "Safe"))


class UpdateMispFailureTest(TestCase):
    def test_failed_push_surfaces_but_other_objects_are_still_pushed(self):
        svc = MISPService.__new__(MISPService)
        svc.client, svc.primary = MagicMock(), True
        ioc = MagicMock()
        case = SimpleNamespace(
            id=1, results="Safe", fileOrMail=None,
            nonFileIocs=SimpleNamespace(get_iocs=lambda: {"url": ioc, "ip": ioc}),
        )
        pushed = []

        def fake_add(event_id, artifact, case_number, level, ioc_type=None, **kw):
            pushed.append(ioc_type)
            if ioc_type == "url":
                raise RuntimeError("boom")

        with patch("connectors.contrib.misp.service.MISPEventManager") as mem, \
                patch.object(MISPService, "add_artifact_object", side_effect=fake_add):
            mem.return_value.get_or_create_event.return_value = MagicMock(id=1)
            with self.assertRaises(RuntimeError):
                svc.update_misp(case)
        self.assertEqual(pushed, ["url", "ip"])

    def test_missing_event_raises(self):
        svc = MISPService.__new__(MISPService)
        svc.client, svc.primary = MagicMock(), True
        with patch("connectors.contrib.misp.service.MISPEventManager") as mem:
            mem.return_value.get_or_create_event.return_value = None
            with self.assertRaises(RuntimeError):
                svc.update_misp(SimpleNamespace(id=1, results="Safe"))


class ManifestTest(SimpleTestCase):
    def test_enabled_by_default(self):
        self.assertTrue(MISPConnector.manifest.enabled_by_default)


class EventLockTest(SimpleTestCase):
    def test_lock_is_exclusive_and_released(self):
        from django.core.cache import cache
        from connectors.contrib.misp.events import _event_lock
        cache.delete("misp_event_lock:t")
        with _event_lock("t"):
            with self.assertRaises(RuntimeError):
                with _event_lock("t", wait=0.3):
                    pass
        with _event_lock("t", wait=0.3):  # released after the first block
            pass
