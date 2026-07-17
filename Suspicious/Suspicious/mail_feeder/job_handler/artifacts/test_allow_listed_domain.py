from django.contrib.auth import get_user_model
from django.test import TestCase

from domain_process.models import Domain
from settings.models import AllowListDomain, WatcherLegitDomain
from mail_feeder.job_handler.artifacts.artifacts import ArtifactJobLauncherService


class AllowListedDomainSkipTest(TestCase):
    """A domain in the allow-list must be recognised as allow-listed (and thus
    skipped from Cortex dispatch) even when it is NOT also in the separate
    Watcher-legit table. The old code AND-ed the two lists, so ordinary
    allow-listed domains were still sent to analysis — flooding the queue."""

    def setUp(self):
        self.user = get_user_model().objects.create_user(username="al_u", password="x")

    def _domain(self, value):
        return Domain.objects.create(value=value)

    def test_allow_list_only_domain_is_allow_listed(self):
        domain = self._domain("safe.example.com")
        AllowListDomain.objects.create(domain=domain, user=self.user)
        svc = ArtifactJobLauncherService()
        self.assertTrue(svc._is_domain_allow_listed(domain))

    def test_watcher_legit_only_domain_is_allow_listed(self):
        domain = self._domain("legit.example.com")
        WatcherLegitDomain.objects.create(domain=domain, watcher_id=1)
        svc = ArtifactJobLauncherService()
        self.assertTrue(svc._is_domain_allow_listed(domain))

    def test_unlisted_domain_is_not_allow_listed(self):
        domain = self._domain("unknown.example.com")
        svc = ArtifactJobLauncherService()
        self.assertFalse(svc._is_domain_allow_listed(domain))
