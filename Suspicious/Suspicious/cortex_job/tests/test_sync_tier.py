"""Newly-synced/created analyzers must be tiered by name prefix, not left at the
field default. Covers both runtime creation sites (sync_cortex cron and
CortexJob.get_analyzer_db)."""
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase

from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from cortex_job.models import Analyzer
from tasp.cron import sync_cortex


def _analyzer(name, cid):
    return SimpleNamespace(name=name, id=cid)


class SyncCortexTierTests(TestCase):
    def _run_sync(self, remote):
        with mock.patch.object(sync_cortex, "SessionCortexApi"), \
             mock.patch.object(sync_cortex, "load_config", return_value=mock.Mock()), \
             mock.patch.object(sync_cortex, "_fetch_all_analyzers", return_value=remote):
            sync_cortex.sync_cortex_analyzers()

    def test_new_analyzers_tiered_by_prefix(self):
        self._run_sync([
            _analyzer("VirusTotal_GetReport_9_9", "c1"),
            _analyzer("Whatever_1_0", "c2"),
        ])
        self.assertEqual(Analyzer.objects.get(name="VirusTotal_GetReport_9_9").tier, 1)
        self.assertEqual(Analyzer.objects.get(name="Whatever_1_0").tier, 3)

    def test_manual_tier_override_not_reset_on_resync(self):
        Analyzer.objects.create(
            name="AbuseIPDB_1_0", analyzer_cortex_id="old", tier=1, is_active=True
        )
        self._run_sync([_analyzer("AbuseIPDB_1_0", "new")])
        row = Analyzer.objects.get(name="AbuseIPDB_1_0")
        self.assertEqual(row.tier, 1)  # not clobbered back to default 3
        self.assertEqual(row.analyzer_cortex_id, "new")  # defaults still applied


class GetAnalyzerDbTierTests(TestCase):
    def test_created_analyzer_gets_tier(self):
        row = CortexJob.get_analyzer_db(_analyzer("VirusTotal_GetReport_5_0", "x1"))
        self.assertEqual(row.tier, 1)
        row2 = CortexJob.get_analyzer_db(_analyzer("Shodan_Host_1_0", "x2"))
        self.assertEqual(row2.tier, 3)
