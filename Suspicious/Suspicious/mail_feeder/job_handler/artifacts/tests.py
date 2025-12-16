from unittest import TestCase
from unittest.mock import patch, MagicMock

from mail_feeder.job_handler.artifacts.artifacts import ArtifactJobLauncherService


class ArtifactJobLauncherServiceTests(TestCase):

    def setUp(self):
        self.service = ArtifactJobLauncherService()

    def _artifact(self, artifact_type, **kwargs):
        art = MagicMock()
        art.artifact_type = artifact_type
        for k, v in kwargs.items():
            setattr(art, k, v)
        return art

    @patch("mail_feeder.job_handler.artifacts.artifacts.CortexJob")
    def test_process_ip_artifact_launches_job(self, m_cortex):
        m_cortex.return_value.launch_cortex_jobs.return_value = [1]

        ip = MagicMock(address="1.1.1.1")
        artifact = self._artifact(
            "IP",
            artifactIsIp=MagicMock(ip=ip)
        )

        result = self.service.process_artifacts([artifact])

        self.assertEqual(result, [1])
        m_cortex.return_value.launch_cortex_jobs.assert_called_once_with(ip, "ip")

    @patch("mail_feeder.job_handler.artifacts.artifacts.AllowListFile")
    @patch("mail_feeder.job_handler.artifacts.artifacts.CortexJob")
    def test_hash_allow_listed_skips_cortex(self, m_cortex, m_allow):
        m_allow.objects.filter.return_value.exists.return_value = True

        hash_obj = MagicMock()
        artifact = self._artifact(
            "Hash",
            artifactIsHash=MagicMock(hash=hash_obj)
        )

        result = self.service.process_artifacts([artifact])

        self.assertEqual(result, [])
        m_cortex.assert_not_called()
        self.assertEqual(hash_obj.ioc_level, "SAFE-ALLOW_LISTED")

    @patch("mail_feeder.job_handler.artifacts.artifacts.URLHandler")
    @patch("mail_feeder.job_handler.artifacts.artifacts.AllowListDomain")
    @patch("mail_feeder.job_handler.artifacts.artifacts.CortexJob")
    def test_url_domain_allow_listed_skips_job(
        self, m_cortex, m_allow, m_urlhandler
    ):
        m_urlhandler.return_value.get_domain.return_value = "example.com"
        m_allow.objects.filter.return_value.exists.return_value = True

        url = MagicMock(address="http://example.com")
        artifact = self._artifact(
            "URL",
            artifactIsUrl=MagicMock(url=url)
        )

        with patch("domain_process.models.Domain") as m_domain:
            m_domain.objects.filter.return_value.first.return_value = MagicMock()
            result = self.service.process_artifacts([artifact])

        self.assertEqual(result, [])
        m_cortex.assert_not_called()

    @patch("mail_feeder.job_handler.artifacts.artifacts.CortexJob")
    def test_domain_not_allow_listed_launches_job(self, m_cortex):
        m_cortex.return_value.launch_cortex_jobs.return_value = [42]

        domain = MagicMock()
        artifact = self._artifact(
            "Domain",
            artifactIsDomain=MagicMock(domain=domain)
        )

        with patch(
            "mail_feeder.job_handler.artifacts.artifacts.AllowListDomain.objects.filter"
        ) as m_filter:
            m_filter.return_value.exists.return_value = False
            result = self.service.process_artifacts([artifact])

        self.assertEqual(result, [42])
        m_cortex.return_value.launch_cortex_jobs.assert_called_once_with(domain, "domain")

    def test_mail_internal_address_is_skipped(self):
        mail = MagicMock(is_internal=True, address="a@local")
        artifact = self._artifact(
            "MailAddress",
            artifactIsMailAddress=MagicMock(mail_address=mail)
        )

        result = self.service.process_artifacts([artifact])

        self.assertEqual(result, [])

    def test_invalid_artifact_type_is_ignored(self):
        artifact = MagicMock(artifact_type=None)
        result = self.service.process_artifacts([artifact])
        self.assertEqual(result, [])

    @patch("mail_feeder.job_handler.artifacts.artifacts.CortexJob")
    def test_cortex_exception_is_caught(self, m_cortex):
        m_cortex.return_value.launch_cortex_jobs.side_effect = Exception("boom")

        ip = MagicMock(address="8.8.8.8")
        artifact = self._artifact(
            "IP",
            artifactIsIp=MagicMock(ip=ip)
        )

        result = self.service.process_artifacts([artifact])
        self.assertEqual(result, [])
