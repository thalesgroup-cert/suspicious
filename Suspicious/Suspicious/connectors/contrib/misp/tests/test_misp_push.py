from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import (
    ArtifactIsDomain, ArtifactIsIp, ArtifactIsUrl, Mail, MailArtifact, MailHeader,
)
from settings.models import CampaignDomainAllowList

from connectors.contrib.misp.connector import MISPConnector
from connectors.contrib.misp.events import MISPEventManager
from connectors.contrib.misp.objects import build_hash_object
from connectors.contrib.misp.service import MISPService
from domain_process.models import Domain
from url_process.models import URL


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

    def test_spoofed_company_sender_is_left_out_with_its_display_name(self):
        attrs = self._email({"from": "Jane CEO <ceo@corp.example>", "to": "x@ext.test"})
        self.assertNotIn("from", attrs)
        self.assertNotIn("from-display-name", attrs)
        self.assertEqual(attrs["to"], "x@ext.test")

    def test_external_sender_keeps_its_display_name(self):
        attrs = self._email({"from": "Jane CEO <evil@bad.test>"})
        self.assertEqual(attrs["from"], "evil@bad.test")
        self.assertEqual(attrs["from-display-name"], "Jane CEO")

    def test_company_reply_to_and_return_path_are_left_out(self):
        attrs = self._email({"from": "evil@bad.test", "reply-to": "boss@corp.example",
                             "return-path": "<bounce@mail.corp.example>"})
        self.assertNotIn("reply-to", attrs)
        self.assertNotIn("return-path", attrs)

    def test_external_reply_to_and_return_path_are_kept(self):
        attrs = self._email({"from": "evil@bad.test", "reply-to": "<drop@bad.test>",
                             "return-path": "<bounce@bad.test>"})
        self.assertEqual(attrs["reply-to"], "drop@bad.test")
        self.assertEqual(attrs["return-path"], "bounce@bad.test")

    def test_repeated_header_values_are_filtered_too(self):
        from connectors.contrib.misp.internal import external_addresses
        self.assertEqual(
            external_addresses(["jane@corp.example", "partner@ext.test"], self.COMPANY),
            "partner@ext.test",
        )


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

    def test_allow_listed_domains_match_exactly_so_subdomains_still_share(self):
        svc = self._svc()
        build = lambda v: svc._build_artifact_object(  # noqa: E731
            Domain(value=v), 1, "Dangerous", "domain")
        self.assertIsNone(build("good.test"))
        self.assertIsNotNone(build("evil.good.test"))
        self.assertIsNotNone(build("notgood.test"))

    def test_allow_listed_url_hosts_match_exactly(self):
        svc = self._svc()
        build = lambda a: svc._build_artifact_object(  # noqa: E731
            URL(address=a), 1, "Dangerous", "url")
        self.assertIsNone(build("https://good.test/x"))
        self.assertIsNotNone(build("https://evil.good.test/x"))


class CompanyUrlsStayOutOfMispTest(SimpleTestCase):
    def _svc(self):
        svc = MISPService.__new__(MISPService)
        svc._company_domains = frozenset({"corp.example"})
        svc._allow_listed = frozenset()
        return svc

    def test_urls_on_company_hosts_are_skipped(self):
        svc = self._svc()
        build = lambda a: svc._build_artifact_object(  # noqa: E731
            URL(address=a), 1, "Dangerous", "url")
        self.assertIsNone(build("https://corp.example/login"))
        self.assertIsNone(build("https://portal.corp.example:8443/a?b=c"))
        self.assertIsNone(build("HTTPS://Portal.Corp.Example./a"))
        self.assertIsNotNone(build("https://evil.test/login"))

    def test_lookalike_and_embedded_company_names_are_kept(self):
        svc = self._svc()
        build = lambda a: svc._build_artifact_object(  # noqa: E731
            URL(address=a), 1, "Dangerous", "url")
        self.assertIsNotNone(build("https://notcorp.example/x"))
        self.assertIsNotNone(build("https://corp.example.evil.test/x"))
        self.assertIsNotNone(build("https://evil.test/?next=https://corp.example/"))
        self.assertIsNotNone(build("https://corp.example@evil.test/x"))

    def test_mail_artifact_urls_are_filtered_too(self):
        svc = self._svc()
        art = lambda a: SimpleNamespace(  # noqa: E731
            artifact_type="URL", artifactIsUrl=SimpleNamespace(url=URL(address=a)))
        self.assertIsNone(svc._build_artifact_object(art("https://corp.example/x"), 1, "Dangerous", None))
        self.assertIsNotNone(svc._build_artifact_object(art("https://evil.test/x"), 1, "Dangerous", None))


class AllowListedAndCampaignIocsStayOutOfMispTest(SimpleTestCase):
    def _svc(self):
        svc = MISPService.__new__(MISPService)
        svc._company_domains = frozenset({"corp.example", "sim.test"})  # update_misp merges campaign domains in
        svc._allow_listed = frozenset({"good.test"})
        svc._allow_listed_ips = frozenset({"8.8.8.8", "2606:4700:4700::1111"})
        svc._allow_listed_hashes = frozenset({"ab" * 16})
        return svc

    def _build(self, artifact, ioc_type):
        return self._svc()._build_artifact_object(artifact, 1, "Dangerous", ioc_type)

    def test_campaign_domain_and_subdomains_skipped(self):
        self.assertIsNone(self._build(Domain(value="sim.test"), "domain"))
        self.assertIsNone(self._build(Domain(value="mail.sim.test"), "domain"))
        self.assertIsNotNone(self._build(Domain(value="notsim.test"), "domain"))

    def test_url_host_judged_after_credentials_are_stripped(self):
        self.assertIsNone(self._build(URL(address="https://corp.example@sim.test/x"), "url"))
        self.assertIsNotNone(self._build(URL(address="https://sim.test@evil.test/x"), "url"))

    def test_url_on_allow_listed_domain_skipped_lookalikes_pushed(self):
        self.assertIsNone(self._build(URL(address="https://good.test/a"), "url"))
        self.assertIsNotNone(self._build(URL(address="https://cdn.good.test/a"), "url"))  # exact match
        self.assertIsNotNone(self._build(URL(address="https://good.test.evil.tld/a"), "url"))
        self.assertIsNotNone(self._build(URL(address="https://evil.test/?u=https://good.test/"), "url"))

    def test_allow_listed_ip_and_hash_skipped_others_pushed(self):
        self.assertIsNone(self._build(IP(address="2606:4700:4700:0:0:0:0:1111"), "ip"))
        self.assertIsNotNone(self._build(IP(address="8.8.4.4"), "ip"))
        self.assertIsNone(self._build(Hash(value="AB" * 16, hashtype="md5"), "hash"))
        self.assertIsNotNone(self._build(Hash(value="cd" * 16, hashtype="md5"), "hash"))

    def test_mail_artifact_ip_and_attachment_hash_filtered_too(self):
        svc = self._svc()
        art = SimpleNamespace(artifact_type="IP", artifactIsIp=SimpleNamespace(ip=IP(address="8.8.8.8")))
        self.assertIsNone(svc._build_artifact_object(art, 1, "Dangerous", None))
        att = SimpleNamespace(id=1, file=SimpleNamespace(linked_hash=Hash(value="ab" * 16, hashtype="md5")))
        with patch.object(MISPService, "_push") as push:
            svc.add_attachment_object("1", att, 1, "Dangerous")
        push.assert_not_called()

    def test_service_built_without_the_new_sets_still_works(self):
        svc = MISPService.__new__(MISPService)
        svc._company_domains, svc._allow_listed = frozenset(), frozenset()
        self.assertIsNotNone(svc._build_artifact_object(IP(address="8.8.8.8"), 1, "Dangerous", "ip"))


class CampaignSenderCaseStillSharesOtherIocsTest(TestCase):
    def test_campaign_domain_withheld_but_rest_of_case_pushed(self):
        user = get_user_model().objects.create_user(username="misp_camp", password="x")
        CampaignDomainAllowList.objects.create(domain=Domain.objects.create(value="sim.test"), user=user)
        mail = Mail.objects.create(subject="t", mail_from="hr@sim.test", date=timezone.now())
        art = MailArtifact.objects.create(mail=mail, artifact_type="IP", artifact_score=0, artifact_confidence=0)
        art.artifactIsIp = ArtifactIsIp.objects.create(ip=IP.objects.create(address="203.0.113.9"), artifact=art)
        art.save(update_fields=["artifactIsIp"])
        case = Case.objects.create(description="", reporter=user, results="Safe")
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save(update_fields=["fileOrMail"])
        with patch("connectors.contrib.misp.service.MISPEventManager") as mem, \
                patch("connectors.contrib.misp.service.MISPClient"), \
                patch("connectors.contrib.misp.service.build_email_object", return_value=None) as email, \
                patch("connectors.contrib.misp.service.build_ip_object", return_value=MagicMock()) as ip_obj, \
                patch("connectors.contrib.misp.service.finalize_misp_object"), \
                patch.object(MISPService, "_maybe_push_monthly"):
            mem.return_value.get_or_create_event.return_value = MagicMock(id=1)
            svc = MISPService.__new__(MISPService)
            svc.client, svc.primary = MagicMock(), True
            svc.update_misp(case)
        self.assertIn("sim.test", email.call_args.args[3])  # address objects drop the campaign sender
        ip_obj.assert_called_once()                          # no whole-case skip


class UpdateMispAllowListQueriesTest(TestCase):
    def _case(self, user, n_ips, sender_is_campaign=False):
        mail = Mail.objects.create(subject="t", mail_from="hr@sim.test", date=timezone.now())
        if sender_is_campaign:
            mail.mail_header = MailHeader.objects.create(
                header_value="From: HR <hr@sim.test>\nTo: bob@other.test\nSubject: t\n",
                fuzzy_hash="x",
            )
            mail.save(update_fields=["mail_header"])
        for i in range(n_ips):
            art = MailArtifact.objects.create(mail=mail, artifact_type="IP", artifact_score=0, artifact_confidence=0)
            art.artifactIsIp = ArtifactIsIp.objects.create(
                ip=IP.objects.create(address="203.0.113.%d" % (i + 1)), artifact=art)
            art.save(update_fields=["artifactIsIp"])
        case = Case.objects.create(description="", reporter=user, results="Safe")
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save(update_fields=["fileOrMail"])
        return case, mail

    def _run(self, case):
        pushed = []
        with patch("connectors.contrib.misp.service.MISPEventManager") as mem, \
                patch("connectors.contrib.misp.service.MISPClient"), \
                patch.object(MISPService, "_push", side_effect=lambda eid, obj, *a, **k: pushed.append(obj)):
            mem.return_value.get_or_create_event.return_value = MagicMock(id=1)
            svc = MISPService.__new__(MISPService)
            svc.client, svc.primary = MagicMock(), True
            with CaptureQueriesContext(connection) as ctx:
                svc.update_misp(case)
        return pushed, ctx

    def test_allow_list_queries_do_not_grow_with_iocs(self):
        user = get_user_model().objects.create_user(username="misp_q", password="x")
        counts = []
        for n in (1, 20):
            case, _ = self._case(user, n)
            pushed, ctx = self._run(case)
            self.assertGreaterEqual(len(pushed), n)
            counts.append(sum(1 for q in ctx.captured_queries
                              if "allowlist" in q["sql"].lower() or "campaign" in q["sql"].lower()))
        self.assertGreater(counts[0], 0)
        self.assertEqual(counts[0], counts[1])

    def test_campaign_url_domain_and_sender_dropped_from_pushed_objects(self):
        user = get_user_model().objects.create_user(username="misp_c2", password="x")
        CampaignDomainAllowList.objects.create(domain=Domain.objects.create(value="sim.test"), user=user)
        case, mail = self._case(user, 1, sender_is_campaign=True)
        for kind, rel, model in (("url", "artifactIsUrl", ArtifactIsUrl), ("domain", "artifactIsDomain", ArtifactIsDomain)):
            art = MailArtifact.objects.create(mail=mail, artifact_type=kind, artifact_score=0, artifact_confidence=0)
            if kind == "url":
                link = model.objects.create(url=URL.objects.create(address="https://login.sim.test/x"), artifact=art)
            else:
                link = model.objects.create(domain=Domain.objects.create(value="login.sim.test"), artifact=art)
            setattr(art, rel, link)
            art.save(update_fields=[rel])
        pushed, _ = self._run(case)
        values = [str(a.value) for o in pushed for a in o.Attribute]
        self.assertIn("203.0.113.1", values)  # the other IOC is still shared
        self.assertFalse([v for v in values if "sim.test" in v], values)
