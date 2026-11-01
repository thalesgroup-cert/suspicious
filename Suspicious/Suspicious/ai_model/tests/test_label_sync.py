"""The ai_model connector's nightly sync of the review folders into the label ledger (Plan D, Task 5)."""
import json
from unittest import mock

from django.test import TestCase

from ai_model.models import LabelRecord, LabelSyncState
from connectors.contrib.ai_model import connector as module
from connectors.contrib.ai_model import imap_sync
from connectors.contrib.ai_model.connector import AiModelConnector
from connectors.contrib.ai_model.tests.fake_imap import FakeImap
from connectors.contrib.ai_model.tests.test_imap_sync import forward
from connectors.providers import ProviderUnavailable

PHISH, SPAM = "2_CLASSIC_PHISHING", "1_SPAM"
CONFIG = {"url": "http://ai_inference:8090", "token": "s3cret-token", "imap_host": "imap.example",
          "imap_user": "reviewer", "imap_password": "imap-pa55", "imap_folders": f"{PHISH}, {SPAM}, 9_ODD"}


def embed_answer(texts, profile):
    return {"vectors": [[float(len(t)), 1.0 if profile == "campaign" else 0.0] for t in texts],
            "preprocessing_version": "legacy-first128", "embedding_version": "cmp-e1"}


class LabelSyncTest(TestCase):
    def setUp(self):
        self.imap = FakeImap({
            PHISH: {"uidvalidity": 7, "messages": {u: forward(u) for u in (1, 2, 3)}},
            SPAM: {"uidvalidity": 3, "messages": {10: forward(10), 11: b"not a forward"}},
            "9_ODD": {"uidvalidity": 1, "messages": {1: forward(50)}},
        })

    def run_sync(self, config=CONFIG, embed=embed_answer, connect=None):
        connect = connect or mock.Mock(return_value=self.imap)
        with mock.patch.object(imap_sync, "connect", connect), \
                mock.patch.object(module.AiInferenceClient, "embed", side_effect=embed) as call:
            AiModelConnector(config).sync()
        return call, connect

    def test_no_imap_host_does_nothing(self):
        call, connect = self.run_sync(config={**CONFIG, "imap_host": ""})
        connect.assert_not_called()
        call.assert_not_called()
        self.assertFalse(LabelSyncState.objects.exists())

    def test_reads_known_folders_embeds_both_profiles_and_checkpoints(self):
        call, connect = self.run_sync()
        connect.assert_called_once_with("imap.example", 993, "reviewer", "imap-pa55", True)
        selected = [c[1:] for c in self.imap.commands if c[0] == "SELECT"]
        self.assertEqual(selected, [(f'"{PHISH}"', True), (f'"{SPAM}"', True)])  # 9_ODD: no known class
        self.assertEqual([c.args[1] for c in call.call_args_list], ["classifier", "campaign"] * 2)
        self.assertEqual(LabelRecord.objects.filter(label=PHISH).count(), 3)
        self.assertEqual(LabelRecord.objects.filter(label=SPAM, label_class="Unwanted").count(), 1)
        row = LabelRecord.objects.get(message_id="id.1@evil.example")
        self.assertEqual(json.loads(row.campaign_embedding)[1], 1.0)
        phish, spam = LabelSyncState.objects.get(folder=PHISH), LabelSyncState.objects.get(folder=SPAM)
        self.assertEqual((phish.last_uid, phish.uidvalidity, phish.skipped), (3, 7, 0))
        self.assertEqual((spam.last_uid, spam.uidvalidity, spam.skipped), (11, 3, 1))
        self.assertIsNotNone(phish.last_run_at)
        self.assertFalse(LabelSyncState.objects.filter(folder="9_ODD").exists())

    def test_embeds_in_batches_of_32(self):
        self.imap.folders[PHISH]["messages"] = {u: forward(u) for u in range(1, 41)}
        call, _ = self.run_sync(config={**CONFIG, "imap_folders": PHISH})
        self.assertEqual([len(c.args[0]) for c in call.call_args_list], [32, 32, 8, 8])

    def test_the_folder_cap_holds_across_runs(self):
        self.imap.folders[PHISH]["messages"] = {u: forward(u) for u in range(1, 8)}
        with mock.patch.object(module, "FOLDER_BATCH", 3):
            self.run_sync(config={**CONFIG, "imap_folders": PHISH})
            self.assertEqual((LabelRecord.objects.count(), LabelSyncState.objects.get().last_uid), (3, 3))
            self.run_sync(config={**CONFIG, "imap_folders": PHISH})
            self.assertEqual((LabelRecord.objects.count(), LabelSyncState.objects.get().last_uid), (6, 6))

    def test_a_uidvalidity_change_rereads_without_duplicating(self):
        self.run_sync()
        self.imap.folders[PHISH] = {"uidvalidity": 8, "messages": {21: forward(1), 22: forward(4)}}
        call, _ = self.run_sync()
        self.assertEqual(LabelRecord.objects.filter(label=PHISH).count(), 4)
        state = LabelSyncState.objects.get(folder=PHISH)
        self.assertEqual((state.uidvalidity, state.last_uid), (8, 22))
        self.assertEqual([len(c.args[0]) for c in call.call_args_list], [1, 1])  # only the new mail

    def test_a_login_failure_raises_without_credentials(self):
        connect = mock.Mock(side_effect=imap_sync.ImapLoginFailed("error"))
        with self.assertRaises(imap_sync.ImapLoginFailed) as caught:
            self.run_sync(connect=connect)
        self.assertNotIn("imap-pa55", str(caught.exception))
        self.assertNotIn("reviewer", str(caught.exception))

    def test_embed_unavailable_leaves_the_checkpoint_for_a_retry(self):
        with self.assertRaises(ProviderUnavailable):
            self.run_sync(embed=ProviderUnavailable("inference server HTTP 503"))
        self.assertFalse(LabelRecord.objects.exists())
        self.assertFalse(LabelSyncState.objects.filter(last_uid__gt=0).exists())
        self.run_sync()
        self.assertEqual(LabelSyncState.objects.get(folder=PHISH).last_uid, 3)

    def test_a_missing_folder_is_skipped_and_the_others_still_sync(self):
        del self.imap.folders[PHISH]
        self.run_sync()
        self.assertEqual(LabelSyncState.objects.get(folder=SPAM).last_uid, 11)

    def test_a_lost_connection_fails_the_run(self):
        self.imap.errors["SEARCH"] = OSError("reset")
        with self.assertRaises(imap_sync.ImapConnectionLost):
            self.run_sync()
