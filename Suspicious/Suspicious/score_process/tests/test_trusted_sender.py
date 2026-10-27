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
