from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, TestCase

from connectors.contrib.misp.connector import MISPConnector
from connectors.contrib.misp.events import MISPEventManager
from connectors.contrib.misp.objects import build_hash_object
from connectors.contrib.misp.service import MISPService
from domain_process.models import Domain


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


class CompanyDomainsStayOutOfMispTest(SimpleTestCase):
    COMPANY = frozenset({"corp.example"})

    def _email(self, headers):
        from connectors.contrib.misp.objects import build_email_object
        mail = SimpleNamespace(mail_header=SimpleNamespace(header_value=headers), subject="s")
        obj = build_email_object(mail, 1, "Dangerous", self.COMPANY)
        return {a.object_relation: a.value for a in obj.attributes}

    def test_company_recipients_are_left_out(self):
        attrs = self._email({"from": "evil@bad.test", "to": "Jane Doe <jane@corp.example>",
                             "cc": "bob@eu.corp.example"})
        for relation in ("to", "cc", "to-display-name"):
            self.assertNotIn(relation, attrs)
        self.assertEqual(attrs["from"], "evil@bad.test")

    def test_external_recipients_are_kept_and_company_ones_dropped(self):
        attrs = self._email({"from": "evil@bad.test",
                             "to": "jane@corp.example, partner@ext.test"})
        self.assertEqual(attrs["to"], "partner@ext.test")
        self.assertNotIn("to-display-name", attrs)

    def test_lookalike_domain_is_not_a_company_domain(self):
        attrs = self._email({"from": "evil@bad.test", "to": "x@notcorp.example"})
        self.assertEqual(attrs["to"], "x@notcorp.example")


class CompanyDomainObjectsTest(SimpleTestCase):
    def _svc(self):
        svc = MISPService.__new__(MISPService)
        svc._company_domains = frozenset({"corp.example"})
        svc._allow_listed = frozenset({"good.test"})
        return svc

    def test_company_subdomain_allow_listed_and_plain_domains(self):
        svc = self._svc()
        build = lambda v: svc._build_artifact_object(  # noqa: E731
            Domain(value=v), 1, "Dangerous", "domain")
        self.assertIsNone(build("corp.example"))
        self.assertIsNone(build("mail.corp.example"))
        self.assertIsNone(build("good.test"))
        self.assertIsNotNone(build("evil.test"))

    def test_mail_artifact_domains_are_filtered_too(self):
        svc = self._svc()
        art = lambda v: SimpleNamespace(  # noqa: E731
            artifact_type="Domain",
            artifactIsDomain=SimpleNamespace(domain=Domain(value=v)))
        self.assertIsNone(svc._build_artifact_object(art("corp.example"), 1, "Dangerous", None))
        self.assertIsNotNone(svc._build_artifact_object(art("evil.test"), 1, "Dangerous", None))
