# score_process/tests/test_bands.py
from django.test import SimpleTestCase

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
