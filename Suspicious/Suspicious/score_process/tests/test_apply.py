from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, Result
from score_process.scoring.apply import apply_verdict
from score_process.scoring.engine import CaseVerdict


class ApplyVerdictTest(TestCase):
    def test_writes_case_fields(self):
        user = get_user_model().objects.create_user(username="ap_u", password="x")
        case = Case.objects.create(description="", reporter=user)
        v = CaseVerdict(final_score=9, final_confidence=90,
                        result=Result.DANGEROUS, n_malicious=2, n_scored=4)
        apply_verdict(case, v)
        case.refresh_from_db()
        self.assertEqual(case.results, Result.DANGEROUS)
        self.assertEqual(case.final_score, 9)
        self.assertEqual(case.final_confidence, 90)
        self.assertEqual(case.score, 9)
        self.assertEqual(case.confidence, 90)
        self.assertEqual(case.analysis_done, 4)
        self.assertTrue(case.kpi_counted)


class StickyAllowListTests(TestCase):
    def _case(self, **artifact):
        from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
        from django.contrib.auth.models import User
        user = User.objects.create_user("st_u", password="p")
        group = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(group=group, **artifact)
        return Case.objects.create(description="t", reporter=user, observable_group=group), user

    def test_web_allow_listed_ip_keeps_zero_100_and_level(self):
        from ip_process.models import IP
        from score_process.scoring.apply import finalise_ioc_group
        ip = IP.objects.create(address="198.51.100.9")
        ip.update_allow_listed()
        case, _ = self._case(artifact_type="IP", ip=ip)
        finalise_ioc_group(case)
        ip.refresh_from_db()
        self.assertEqual((ip.ioc_score, ip.ioc_confidence, ip.ioc_level), (0, 100, "SAFE-ALLOW_LISTED"))

    def test_sticky_allow_listed_level_is_dropped_once_the_domain_is_campaign_listed(self):
        from domain_process.models import Domain
        from score_process.scoring.apply import finalise_ioc_group
        from settings.models import CampaignDomainAllowList
        d = Domain.objects.create(value="sim.example")
        d.ioc_level, d.ioc_score, d.ioc_confidence = "SAFE-ALLOW_LISTED", 0, 100
        d.save()
        case, user = self._case(artifact_type="DOMAIN", domain=d)
        CampaignDomainAllowList.objects.create(domain=d, user=user)
        finalise_ioc_group(case)
        d.refresh_from_db()
        self.assertEqual(d.ioc_level, "malicious")  # re-scored, not kept Safe
