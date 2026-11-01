"""ai_model_backfill_labels: verdict and proposal rows for existing cases, and the review-folder
sync without its per-run cap (Plan D, Task 7)."""
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError

from django.test import TestCase

from ai_model.models import LabelRecord
from ai_model.tests.test_label_sync import CONFIG, PHISH, embed_answer
from ai_model.tests.test_ledger import CaseMixin
from connectors.contrib.ai_model import connector as module
from connectors.contrib.ai_model import imap_sync
from connectors.contrib.ai_model.connector import AiModelConnector
from connectors.contrib.ai_model.tests.fake_imap import FakeImap
from connectors.contrib.ai_model.tests.test_imap_sync import forward

COMMAND = "ai_model_backfill_labels"


class BackfillLabelsTest(CaseMixin, TestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch("ai_model.ledger.enabled", return_value=True)
        self.enabled = patcher.start()
        self.addCleanup(patcher.stop)
        self.reviewed = self.make_case(results="Dangerous", last_update_by=self.user)
        self.challenged = self.make_case("<b@x>", challenge_proposed_result="Safe")
        self.untouched = self.make_case("<c@x>")

    def run_command(self, *args):
        out = StringIO()
        call_command(COMMAND, *args, stdout=out)
        return out.getvalue()

    def test_records_verdicts_and_proposals_once(self):
        out = self.run_command()
        verdict = LabelRecord.objects.get(source="analyst_verdict")
        self.assertEqual((verdict.case, verdict.label_class), (self.reviewed, "Dangerous"))
        proposal = LabelRecord.objects.get(source="challenge")
        self.assertEqual((proposal.case, proposal.label_class), (self.challenged, "Safe"))
        self.assertIn("1 verdict", out)
        self.assertIn("1 proposal", out)
        self.run_command()
        self.assertEqual(LabelRecord.objects.count(), 2)

    def test_dry_run_writes_nothing(self):
        out = self.run_command("--dry-run")
        self.assertFalse(LabelRecord.objects.exists())
        self.assertIn("1 verdict", out)
        self.assertNotIn(self.user.username + "@", out)

    def test_refuses_when_disabled(self):
        self.enabled.return_value = False
        with self.assertRaises(CommandError):
            self.run_command()
        self.assertFalse(LabelRecord.objects.exists())

    def test_folders_refuses_without_an_imap_host(self):
        with mock.patch("connectors.registry.registry.instantiate",
                        return_value=AiModelConnector({**CONFIG, "imap_host": ""})):
            with self.assertRaises(CommandError):
                self.run_command("--folders")

    def test_folders_syncs_past_the_per_run_cap(self):
        imap = FakeImap({PHISH: {"uidvalidity": 7, "messages": {u: forward(u) for u in range(1, 8)}}})
        connector = AiModelConnector({**CONFIG, "imap_folders": PHISH})
        with mock.patch("connectors.registry.registry.instantiate", return_value=connector), \
                mock.patch.object(imap_sync, "connect", return_value=imap), \
                mock.patch.object(module, "FOLDER_BATCH", 3), \
                mock.patch.object(module.AiInferenceClient, "embed", side_effect=embed_answer):
            out = self.run_command("--folders")
        self.assertEqual(LabelRecord.objects.filter(source="imap_folder").count(), 7)
        self.assertIn("folders", out)
