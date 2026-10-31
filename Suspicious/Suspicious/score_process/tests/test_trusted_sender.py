from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from case_handler.models import Case
from cortex_job.models import Analyzer
from domain_process.models import Domain
from mail_feeder.models import Mail
from score_process.scoring import trusted_sender
from score_process.scoring.collect import collect_votes
from score_process.scoring.engine import AiSignal
from settings.models import AllowListDomain

COMPANY = {"corp.test"}
TRUSTED = ["mx.corp.test"]


def headers(*results, sender="Alice <alice@corp.test>"):
    lines = [f"Authentication-Results: {r}" for r in results]
    return "\n".join(lines + [f"From: {sender}", "To: soc@corp.test", "Subject: hi"]) + "\n\n"


PASS = "mx.corp.test; dkim=pass header.d=corp.test; dmarc=pass header.from=corp.test"


class AuthenticatedSenderTest(SimpleTestCase):
    def ok(self, raw, trusted=TRUSTED):
        return trusted_sender.authenticated_company_sender(raw, trusted, COMPANY)

    def test_a_trusted_gateway_reporting_dmarc_pass_for_a_company_sender(self):
        self.assertTrue(self.ok(headers(PASS)))
        self.assertTrue(self.ok(headers("mx.corp.test; dmarc=pass header.from=mail.corp.test", sender="a@mail.corp.test")))

    def test_a_forged_result_from_an_untrusted_authserv_id_does_not_count(self):
        self.assertFalse(self.ok(headers("evil.example; dmarc=pass header.from=corp.test")))

    def test_without_a_trusted_gateway_configured_nothing_counts(self):
        self.assertFalse(self.ok(headers(PASS), trusted=[]))
        self.assertFalse(self.ok(headers(PASS), trusted=None))

    def test_dmarc_must_pass_and_be_aligned_with_the_from_domain(self):
        self.assertFalse(self.ok(headers("mx.corp.test; dmarc=fail header.from=corp.test")))
        self.assertFalse(self.ok(headers("mx.corp.test; spf=pass; dkim=pass")))
        self.assertFalse(self.ok(headers("mx.corp.test; dmarc=pass header.from=other.test")))

    def test_the_sender_must_be_a_company_domain(self):
        self.assertFalse(self.ok(headers("mx.corp.test; dmarc=pass header.from=evil.test", sender="x@evil.test")))
        self.assertFalse(self.ok(headers(PASS, sender="x@notcorp.test")))
        self.assertFalse(self.ok(headers(PASS, sender="x@corp.test.evil.test")))

    def test_exactly_one_from_header(self):
        two = headers(PASS) .replace("From:", "From: Eve <eve@evil.test>\nFrom:", 1)
        self.assertFalse(self.ok(two))
        self.assertFalse(self.ok(headers(PASS).replace("From: Alice <alice@corp.test>\n", "")))

    def test_a_trusted_result_among_forged_ones_is_found(self):
        self.assertTrue(self.ok(headers("evil.example; dmarc=pass header.from=corp.test", PASS)))

    def test_empty_or_unparseable_headers(self):
        self.assertFalse(self.ok(""))
        self.assertFalse(self.ok("garbage"))


class AllArtifactsListedTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="ts_u", password="x")
        self.mail = Mail.objects.create(subject="s", reportedBy="r", date="2026-01-01T00:00:00Z", to="t", mail_id="m1")

    def test_listed_and_company_artifacts_pass_an_unlisted_one_fails(self):
        AllowListDomain.objects.create(domain=Domain.objects.create(value="partner.test"), user=self.user)
        with patch.object(trusted_sender, "_listed", side_effect=lambda kind, value, d: value in ("https://corp.test/a", "partner.test")):
            self.mail_artifacts_with([("url", "https://corp.test/a"), ("domain", "partner.test")])
            self.assertTrue(trusted_sender.all_artifacts_listed(self.mail, COMPANY))
            self.mail_artifacts_with([("url", "https://evil.test/x")])
            self.assertFalse(trusted_sender.all_artifacts_listed(self.mail, COMPANY))

    def mail_artifacts_with(self, items):
        from unittest.mock import MagicMock
        arts = []
        for kind, value in items:
            art = MagicMock()
            for attr in ("artifactIsUrl", "artifactIsDomain", "artifactIsIp", "artifactIsMailAddress", "artifactIsHash"):
                setattr(art, attr, None)
            link = MagicMock()
            target = MagicMock(address=value, value=value)
            attr, field = {"url": ("artifactIsUrl", "url"), "domain": ("artifactIsDomain", "domain")}[kind]
            setattr(link, field, target)
            setattr(art, attr, link)
            arts.append(art)
        self.mail = MagicMock()
        self.mail.mail_artifacts.all.return_value = arts

    def test_an_attachment_hash_is_never_listed(self):
        from unittest.mock import MagicMock
        art = MagicMock()
        for attr in ("artifactIsUrl", "artifactIsDomain", "artifactIsIp", "artifactIsMailAddress"):
            setattr(art, attr, None)
        art.artifactIsHash = MagicMock()
        self.mail = MagicMock()
        self.mail.mail_artifacts.all.return_value = [art]
        self.assertFalse(trusted_sender.all_artifacts_listed(self.mail, COMPANY))


class OrchestratorTest(TestCase):
    def setUp(self):
        self.case = Case.objects.create(description="", reporter=get_user_model().objects.create_user(username="orc", password="x"))

    def test_off_by_default_and_never_reads_storage(self):
        with patch.object(trusted_sender, "get_config", return_value=None), \
             patch.object(trusted_sender, "read_mail_headers") as read:
            self.assertFalse(trusted_sender.ai_may_be_overruled(self.case))
        read.assert_not_called()

    def test_a_non_mail_case_is_never_overruled(self):
        with patch.object(trusted_sender, "get_config", return_value=TRUSTED):
            self.assertFalse(trusted_sender.ai_may_be_overruled(self.case))

    def test_any_error_fails_closed(self):
        from types import SimpleNamespace
        case = SimpleNamespace(id=1, fileOrMail=SimpleNamespace(mail=SimpleNamespace(mail_id="x")))
        with patch.object(trusted_sender, "get_config", return_value=TRUSTED), \
             patch("common.storage.get_store", side_effect=RuntimeError("store down")):
            self.assertFalse(trusted_sender.ai_may_be_overruled(case))

    def test_all_conditions_met_overrules(self):
        from types import SimpleNamespace
        case = SimpleNamespace(id=1, fileOrMail=SimpleNamespace(mail=SimpleNamespace(mail_id="x")))
        with patch.object(trusted_sender, "get_config", return_value=TRUSTED), \
             patch("common.storage.get_store"), \
             patch("connectors.contrib.misp.internal.company_domains", return_value=COMPANY), \
             patch.object(trusted_sender, "read_mail_headers", return_value=headers(PASS)), \
             patch.object(trusted_sender, "all_artifacts_listed", return_value=True):
            self.assertTrue(trusted_sender.ai_may_be_overruled(case))
        with patch.object(trusted_sender, "get_config", return_value=TRUSTED), \
             patch("common.storage.get_store"), \
             patch("connectors.contrib.misp.internal.company_domains", return_value=COMPANY), \
             patch.object(trusted_sender, "read_mail_headers", return_value=headers(PASS)), \
             patch.object(trusted_sender, "all_artifacts_listed", return_value=False):
            self.assertFalse(trusted_sender.ai_may_be_overruled(case))


class AiVoteWiringTest(TestCase):
    def setUp(self):
        self.case = Case.objects.create(description="", reporter=get_user_model().objects.create_user(username="wir", password="x"))
        Analyzer.objects.create(name="AIMailAnalyzer", analyzer_cortex_id="ai", weight=0.4)

    def vote(self, overridable):
        with patch("cortex_job.cortex_utils.cortex_and_job_management._get_cortex_config",
                   return_value={"analyzers": {"ai": "AIMailAnalyzer"}}), \
             patch("score_process.scoring.trusted_sender.ai_may_be_overruled", return_value=overridable) as chk:
            votes = {v.analyzer: v for v in collect_votes(self.case, AiSignal(score=9, confidence=90))}
        return votes["AIMailAnalyzer"], chk

    def test_an_overridable_ai_dissent_may_be_overruled(self):
        v, _ = self.vote(True)
        self.assertEqual((v.band, v.dissent_on_listed), ("Dangerous", True))

    def test_otherwise_it_blocks_the_override(self):
        v, _ = self.vote(False)
        self.assertEqual((v.band, v.dissent_on_listed), ("Dangerous", False))

    def test_a_safe_ai_does_not_trigger_the_check(self):
        with patch("cortex_job.cortex_utils.cortex_and_job_management._get_cortex_config",
                   return_value={"analyzers": {"ai": "AIMailAnalyzer"}}), \
             patch("score_process.scoring.trusted_sender.ai_may_be_overruled") as chk:
            collect_votes(self.case, AiSignal(score=0, confidence=90))
        chk.assert_not_called()


class ReadMailHeadersTest(TestCase):
    MAIL = "261007071836-7a54e9fcb2f6"

    def setUp(self):
        self.mail = Mail.objects.create(subject="s", reportedBy="r", date="2026-01-01T00:00:00Z", to="t",
                                        mail_id=self.MAIL)

    def store(self, buckets):
        import io

        from common.storage.fake import FakeObjectStore

        store = FakeObjectStore()
        for bucket, objects in buckets.items():
            store.ensure_bucket(bucket)
            for name, data in objects.items():
                store.put(bucket, name, io.BytesIO(data), length=len(data))
        return store

    def archive(self, bucket_name="", members=None):
        import io
        import os
        import tarfile
        import tempfile

        from file_process.models import File
        from hash_process.models import Hash
        from mail_feeder.models import MailArchive

        stored = None
        if members is not None:
            fd, path = tempfile.mkstemp(suffix=".tar.gz")
            os.close(fd)
            self.addCleanup(os.remove, path)
            with tarfile.open(path, "w:gz") as tar:
                for name, data in members.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            stored = File.objects.create(linked_hash=Hash.objects.create(value="h-ts"), tmp_path=path)
        return MailArchive.objects.create(mail=self.mail, archive=stored, bucket_name=bucket_name)

    def read(self, store):
        return trusted_sender.read_mail_headers(store, self.mail)

    def test_the_legacy_bucket_named_after_the_submission(self):
        self.archive("haruto-submission-261007071836")
        store = self.store({"haruto-submission-261007071836": {f"{self.MAIL}/{self.MAIL}.headers": b"From: a@corp.test"}})
        self.assertEqual(self.read(store), "From: a@corp.test")

    def test_a_feeder_mail_stored_under_its_submission_prefix(self):
        self.archive("Haruto_Sato-1")
        store = self.store({"feeder": {f"Haruto_Sato-1/{self.MAIL}/{self.MAIL}.headers": b"From: a@corp.test"}})
        with patch("settings.config.get_section", return_value={"feeder_bucket": "feeder"}):
            self.assertEqual(self.read(store), "From: a@corp.test")

    def test_a_web_upload_has_no_trusted_headers_and_is_never_overruled(self):
        # The uploader wrote the file, so its Authentication-Results prove nothing.
        trusted = headers(PASS).encode()
        self.archive("", {"./ref.txt": b"body", "./ref.headers": trusted})
        store = self.store({
            "mail-submissions": {f"x-submission-1-ab/{self.MAIL}.headers": trusted},
            "x-submission-261007071836": {f"{self.MAIL}/{self.MAIL}.headers": trusted},
        })
        self.assertEqual(self.read(store), "")
        case = Case.objects.create(description="", reporter=get_user_model().objects.create_user(username="ts_w", password="x"))
        from case_handler.models import CaseHasFileOrMail

        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=self.mail)
        case.save(update_fields=["fileOrMail"])
        with patch.object(trusted_sender, "get_config", return_value=TRUSTED), \
             patch("common.storage.get_store", return_value=store), \
             patch("connectors.contrib.misp.internal.company_domains", return_value=COMPANY), \
             patch.object(trusted_sender, "all_artifacts_listed", return_value=True):
            self.assertFalse(trusted_sender.ai_may_be_overruled(case))

    def test_a_feeder_mail_missing_from_the_store_is_not_read_from_its_tar(self):
        self.archive("Haruto_Sato-1", {"./ref.txt": b"body", "./ref.headers": b"From: a@corp.test"})
        with patch("settings.config.get_section", return_value={"feeder_bucket": "feeder"}):
            self.assertEqual(self.read(self.store({"feeder": {}})), "")

    def test_a_mail_with_no_stored_object_and_no_archive_has_no_headers(self):
        self.archive("Haruto_Sato-1")
        with patch("settings.config.get_section", return_value={"feeder_bucket": "feeder"}):
            self.assertEqual(self.read(self.store({"feeder": {}})), "")
        self.assertEqual(self.read(self.store({})), "")

    def test_a_store_outage_propagates_and_the_ai_is_not_overruled(self):
        from common.storage import StoreError

        self.archive("Haruto_Sato-1", {"./ref.txt": b"body", "./ref.headers": headers(PASS).encode()})
        store = self.store({})
        store.list_buckets = store.bucket_exists = lambda *a: (_ for _ in ()).throw(StoreError("unavailable"))
        with self.assertRaises(StoreError):
            self.read(store)
        case = Case.objects.create(description="", reporter=get_user_model().objects.create_user(username="ts_o", password="x"))
        from case_handler.models import CaseHasFileOrMail

        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=self.mail)
        case.save(update_fields=["fileOrMail"])
        with patch.object(trusted_sender, "get_config", return_value=TRUSTED), \
             patch("common.storage.get_store", return_value=store), \
             patch("connectors.contrib.misp.internal.company_domains", return_value=COMPANY), \
             patch.object(trusted_sender, "all_artifacts_listed", return_value=True):
            self.assertFalse(trusted_sender.ai_may_be_overruled(case))
