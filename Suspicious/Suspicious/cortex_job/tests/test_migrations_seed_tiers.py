from django.test import TestCase
from cortex_job.models import Analyzer
from cortex_job.migrations import _tier_seed  # helper module we add alongside migrations


class SeedTierHelperTests(TestCase):
    def test_known_prefixes_map_to_tiers(self):
        self.assertEqual(_tier_seed.tier_for("VirusTotal_GetReport_3_1"), 1)
        self.assertEqual(_tier_seed.tier_for("MISP_2_1"), 1)
        self.assertEqual(_tier_seed.tier_for("AI_Mail_Analyzer_1_4"), 2)
        self.assertEqual(_tier_seed.tier_for("Yara_Boosted_3_2"), 2)
        self.assertEqual(_tier_seed.tier_for("ThreatGridOnPrem_1_0"), 2)
        self.assertEqual(_tier_seed.tier_for("CIRCLHashlookup_1_1"), 2)
        self.assertEqual(_tier_seed.tier_for("AbuseIPDB_1_0"), 3)
        self.assertEqual(_tier_seed.tier_for("Shodan_Host_1_0"), 3)
        self.assertEqual(_tier_seed.tier_for("SomethingUnknown_9_9"), 3)
