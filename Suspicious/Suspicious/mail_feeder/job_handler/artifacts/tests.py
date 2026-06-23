from unittest import TestCase
from unittest.mock import patch, MagicMock
from unittest import mock
import django.test

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

    def test_process_ip_artifact_queues_intent(self):
        ip = MagicMock(address="1.1.1.1")
        artifact = self._artifact(
            "IP",
            artifactIsIp=MagicMock(ip=ip)
        )

        service = self.service.process_artifacts([artifact])

        self.assertIs(service, self.service)
        self.assertEqual(service.pending_dispatch_intents, [(ip, "ip")])

    @patch("mail_feeder.job_handler.artifacts.artifacts.AllowListFile")
    def test_hash_allow_listed_skips_cortex(self, m_allow):
        m_allow.objects.filter.return_value.exists.return_value = True

        hash_obj = MagicMock()
        artifact = self._artifact(
            "Hash",
            artifactIsHash=MagicMock(hash=hash_obj)
        )

        service = self.service.process_artifacts([artifact])

        self.assertEqual(service.pending_dispatch_intents, [])
        self.assertEqual(hash_obj.ioc_level, "SAFE-ALLOW_LISTED")

    @patch("mail_feeder.job_handler.artifacts.artifacts.WatcherLegitDomain")
    @patch("mail_feeder.job_handler.artifacts.artifacts.URLHandler")
    @patch("mail_feeder.job_handler.artifacts.artifacts.AllowListDomain")
    def test_url_domain_allow_listed_skips_job(
        self, m_allow, m_urlhandler, m_watcher
    ):
        m_urlhandler.return_value.get_domain.return_value = "example.com"
        m_allow.objects.filter.return_value.exists.return_value = True
        m_watcher.objects.filter.return_value.exists.return_value = True

        url = MagicMock(address="http://example.com")
        artifact = self._artifact(
            "URL",
            artifactIsUrl=MagicMock(url=url)
        )

        with patch("domain_process.models.Domain") as m_domain:
            m_domain.objects.filter.return_value.first.return_value = MagicMock()
            service = self.service.process_artifacts([artifact])

        self.assertEqual(service.pending_dispatch_intents, [])

    @patch("mail_feeder.job_handler.artifacts.artifacts.WatcherMonitoredDomain")
    @patch("mail_feeder.job_handler.artifacts.artifacts.DenyListDomain")
    @patch("mail_feeder.job_handler.artifacts.artifacts.WatcherLegitDomain")
    @patch("mail_feeder.job_handler.artifacts.artifacts.AllowListDomain")
    def test_domain_not_allow_listed_queues_intent(self, m_allow, m_watcher, m_deny, m_monitored):
        m_allow.objects.filter.return_value.exists.return_value = False
        m_watcher.objects.filter.return_value.exists.return_value = False
        m_deny.objects.filter.return_value.exists.return_value = False
        m_monitored.objects.filter.return_value.exists.return_value = False

        domain = MagicMock()
        artifact = self._artifact(
            "Domain",
            artifactIsDomain=MagicMock(domain=domain)
        )

        service = self.service.process_artifacts([artifact])

        self.assertEqual(service.pending_dispatch_intents, [(domain, "domain")])

    def test_mail_internal_address_is_skipped(self):
        mail = MagicMock(is_internal=True, address="a@local")
        artifact = self._artifact(
            "MailAddress",
            artifactIsMailAddress=MagicMock(mail_address=mail)
        )

        service = self.service.process_artifacts([artifact])

        self.assertEqual(service.pending_dispatch_intents, [])

    def test_invalid_artifact_type_is_ignored(self):
        artifact = MagicMock(artifact_type=None)
        service = self.service.process_artifacts([artifact])
        self.assertEqual(service.pending_dispatch_intents, [])

    @patch("mail_feeder.job_handler.artifacts.artifacts.CortexJob")
    def test_dispatch_pending_exception_is_caught(self, m_cortex):
        m_cortex.return_value.launch_cortex_jobs.side_effect = Exception("boom")

        ip = MagicMock(address="8.8.8.8")
        artifact = self._artifact(
            "IP",
            artifactIsIp=MagicMock(ip=ip)
        )

        service = self.service.process_artifacts([artifact])
        # dispatch_pending should not raise even when launch_cortex_jobs fails
        case = MagicMock()
        job_ids = service.dispatch_pending(case)
        self.assertEqual(job_ids, [])
        # intents cleared after dispatch attempt
        self.assertEqual(service.pending_dispatch_intents, [])

    @patch("mail_feeder.job_handler.artifacts.artifacts.CortexJob")
    def test_dispatch_pending_calls_launch_cortex_jobs(self, m_cortex):
        m_cortex.return_value.launch_cortex_jobs.return_value = [42]

        ip = MagicMock(address="1.2.3.4")
        artifact = self._artifact(
            "IP",
            artifactIsIp=MagicMock(ip=ip)
        )

        service = self.service.process_artifacts([artifact])
        case = MagicMock()
        job_ids = service.dispatch_pending(case)

        self.assertEqual(job_ids, [42])
        m_cortex.return_value.launch_cortex_jobs.assert_called_once_with(ip, "ip", case=case)
        self.assertEqual(service.pending_dispatch_intents, [])


class ArtifactPlannerIntegrationTest(django.test.TestCase):
    """Integration test: ArtifactJobLauncherService.dispatch_pending engages
    the URL planner to reduce redundant Cortex dispatches on mail-origin emails."""

    @mock.patch("mail_feeder.job_handler.artifacts.artifacts.CortexJob")
    @mock.patch("url_process.url_utils.url_planner.get_config")
    def test_planner_collapses_same_fqdn_urls(self, mock_get_config, MockCortex):
        """4 URLs sharing canonical key → planner keeps 1 → Cortex called once."""
        from url_process.models import URL
        mock_get_config.side_effect = lambda k, d=None: {
            "url_analysis.enabled": True,
            "url_analysis.max_per_domain": 1,
            "url_analysis.reuse_ttl_days": 7,
        }.get(k, d)
        MockCortex.return_value.launch_cortex_jobs.return_value = [1]

        urls = [URL.objects.create(address=f"https://x.com/p?id={i}") for i in range(4)]
        service = ArtifactJobLauncherService()
        service.pending_dispatch_intents = [(u, "url") for u in urls]

        case = mock.MagicMock()
        case.id = 99
        # No mail on this case (sender_domain=None path)
        case.fileOrMail = None

        service.dispatch_pending(case)

        # 4 URLs → planner → 1 canonical group capped to 1 → 1 Cortex call
        self.assertEqual(MockCortex.return_value.launch_cortex_jobs.call_count, 1)

    @mock.patch("mail_feeder.job_handler.artifacts.artifacts.CortexJob")
    @mock.patch("url_process.url_utils.url_planner.get_config")
    def test_planner_disabled_dispatches_all(self, mock_get_config, MockCortex):
        """When url_analysis.enabled=False, all URL intents are dispatched."""
        from url_process.models import URL
        mock_get_config.side_effect = lambda k, d=None: {
            "url_analysis.enabled": False,
        }.get(k, d)
        MockCortex.return_value.launch_cortex_jobs.return_value = [1]

        urls = [URL.objects.create(address=f"https://x.com/p?id={i}") for i in range(4)]
        service = ArtifactJobLauncherService()
        service.pending_dispatch_intents = [(u, "url") for u in urls]

        case = mock.MagicMock()
        case.id = 99
        case.fileOrMail = None

        service.dispatch_pending(case)

        self.assertEqual(MockCortex.return_value.launch_cortex_jobs.call_count, 4)
