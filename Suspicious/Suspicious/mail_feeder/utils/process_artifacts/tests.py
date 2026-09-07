from datetime import datetime, timezone as tz

from django.test import TestCase

from mail_feeder.models import Mail, MailArtifact
from mail_feeder.utils.process_artifacts.artifacts import ArtifactService


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
