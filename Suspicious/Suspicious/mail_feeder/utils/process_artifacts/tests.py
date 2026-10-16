from datetime import datetime, timezone as tz
from unittest.mock import patch

from django.test import TestCase

from email_process.models import MailAddress
from mail_feeder.models import Mail, MailArtifact
from mail_feeder.utils.process_artifacts.artifacts import ArtifactService
from mail_feeder.utils.process_artifacts.models import ArtifactModel


class HandleUrlUnwrapTests(TestCase):
    def setUp(self):
        self.mail = Mail.objects.create(
            subject="s", reportedBy="r@x.test",
            date=datetime(2026, 1, 1, tzinfo=tz.utc), to="a@x.test", mail_id="m1",
        )

    def _url_artifacts(self):
        return set(
            MailArtifact.objects
            .filter(mail=self.mail, artifact_type="URL")
            .values_list("artifactIsUrl__url__address", flat=True)
        )

    def test_safelinks_url_links_both_wrapper_and_real_target(self):
        wrapped = ("https://x.safelinks.protection.outlook.com/?url="
                   "https%3A%2F%2Fevil.example.com%2Fphish&reserved=0")
        ArtifactService()._handle_url(wrapped, self.mail)
        addrs = self._url_artifacts()
        self.assertIn("https://evil.example.com/phish", addrs)
        self.assertIn(wrapped, addrs)

    def test_plain_url_links_only_itself(self):
        ArtifactService()._handle_url("https://plain.example.com/page", self.mail)
        self.assertEqual(self._url_artifacts(), {"https://plain.example.com/page"})


class HandleMailValidatorTests(TestCase):
    """Regression: _handle_mail built the validator from a ConfigModel without
    ``own_domains``, so every mail artifact failed with "'ConfigModel' object
    has no attribute 'own_domains'" and was silently dropped."""

    LOGGER = "tasp.cron.fetch_and_process_emails"

    def setUp(self):
        self.mail = Mail.objects.create(
            subject="s", reportedBy="r@x.test",
            date=datetime(2026, 1, 1, tzinfo=tz.utc), to="a@x.test", mail_id="m-addr",
        )
        # The address/domain handler does network lookups; not what is tested here.
        handler = patch(
            "mail_feeder.utils.process_artifacts.artifacts.MailAddressHandler"
        ).start()
        handler.return_value.handle_mail.side_effect = (
            lambda address: MailAddress.objects.get_or_create(address=address)[0]
        )
        self.addCleanup(patch.stopall)

    def _handle(self, address):
        ArtifactService().handle_artifacts(
            [ArtifactModel(dataType="mail", data=address)], self.mail
        )

    def _linked(self, address):
        return MailArtifact.objects.filter(
            mail=self.mail, artifact_type="MailAddress",
            artifactIsMailAddress__mail_address__address=address,
        ).count()

    def test_external_address_is_linked_without_error(self):
        with self.assertNoLogs(self.LOGGER, "ERROR"):
            self._handle("Someone@Elsewhere.example")
        self.assertEqual(self._linked("someone@elsewhere.example"), 1)

    def test_own_domain_and_its_subdomains_are_company_addresses(self):
        with patch(
            "mail_feeder.utils.user_creation.creation._own_domains",
            return_value=["corp.example"],
        ), patch(
            "mail_feeder.utils.process_artifacts.artifacts.UserCreationService.get_or_create_user"
        ) as get_or_create_user, self.assertNoLogs(self.LOGGER, "ERROR"):
            self._handle("jane@eu.corp.example")
        get_or_create_user.assert_called_once_with("jane@eu.corp.example")
        self.assertEqual(self._linked("jane@eu.corp.example"), 0)
