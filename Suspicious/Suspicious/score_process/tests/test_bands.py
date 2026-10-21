# score_process/tests/test_bands.py
from django.test import SimpleTestCase, TestCase

from score_process.scoring import bands


class BandsModuleTests(SimpleTestCase):
    def test_maps_have_the_four_bands(self):
        for m in (bands._BAND_TO_IOC_LEVEL, bands._DERIVED_SCORE):
            self.assertEqual(
                set(m) & {"Safe", "Suspicious", "Dangerous", "Inconclusive"},
                {"Safe", "Suspicious", "Dangerous", "Inconclusive"},
            )

    def test_band_to_ioc_level_values(self):
        self.assertEqual(bands._BAND_TO_IOC_LEVEL["Dangerous"], "malicious")
        self.assertEqual(bands._BAND_TO_IOC_LEVEL["Safe"], "safe")
        self.assertEqual(bands._BAND_TO_IOC_LEVEL["Inconclusive"], "info")

    def test_sticky_set(self):
        self.assertIn("SAFE-ALLOW_LISTED", bands._STICKY_IOC_LEVELS)
        self.assertIn("critical", bands._STICKY_IOC_LEVELS)

    def test_rank_orders_dangerous_highest(self):
        self.assertGreater(bands._BAND_RANK["Dangerous"], bands._BAND_RANK["Suspicious"])
        self.assertEqual(bands._BAND_RANK["Safe"], bands._BAND_RANK["Inconclusive"])


class StickyHoldsTests(TestCase):
    def test_mail_address_lapses_when_its_sender_domain_is_campaign_listed(self):
        from types import SimpleNamespace
        from django.contrib.auth.models import User
        from domain_process.models import Domain
        from score_process.scoring.bands import sticky_holds
        from settings.models import CampaignDomainAllowList
        addr = SimpleNamespace(ioc_level="SAFE-ALLOW_LISTED", address="boss@sim.example")
        self.assertTrue(sticky_holds(addr))
        CampaignDomainAllowList.objects.create(
            domain=Domain.objects.create(value="sim.example"),
            user=User.objects.create_user("sh_u", password="p"))
        self.assertFalse(sticky_holds(addr))

    def test_hash_like_values_skip_the_domain_lookup(self):
        from types import SimpleNamespace
        from score_process.scoring.bands import sticky_holds
        h = SimpleNamespace(ioc_level="SAFE-ALLOW_LISTED", value="ab" * 16)
        with self.assertNumQueries(0):
            self.assertTrue(sticky_holds(h))
