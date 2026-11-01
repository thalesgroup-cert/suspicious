"""The ai_model connector's nightly sync of the review folders into the label ledger (Plan D, Task 5)."""
import json
from datetime import datetime, timezone
from unittest import mock

from django.test import TestCase

from ai_model.models import LabelRecord, LabelSyncState
from ai_model.taxonomy import FOLDERS
from connectors.contrib.ai_model import connector as module
from connectors.contrib.ai_model import imap_sync
from connectors.contrib.ai_model.connector import AiModelConnector
from connectors.contrib.ai_model.tests.fake_imap import FakeImap
from connectors.contrib.ai_model.tests.test_imap_sync import forward, inner
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
        with mock.patch.object(module, "CHUNK", 100):
            call, _ = self.run_sync(config={**CONFIG, "imap_folders": PHISH})
        self.assertEqual([len(c.args[0]) for c in call.call_args_list], [32, 32, 8, 8])

    def test_a_folder_is_read_in_chunks_of_25(self):
        # Fix wave 3: fetch, match and embed of one chunk stay far inside Celery's 540 s soft limit.
        self.imap.folders[PHISH]["messages"] = {u: forward(u) for u in range(1, 41)}
        call, _ = self.run_sync(config={**CONFIG, "imap_folders": PHISH})
        self.assertEqual([len(c.args[0]) for c in call.call_args_list], [25, 25, 15, 15])

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

    def selected(self):
        return [c[1].strip('"') for c in self.imap.commands if c[0] == "SELECT"]

    def test_folders_default_to_the_eight_when_absent_empty_or_blank(self):
        absent = {k: v for k, v in CONFIG.items() if k != "imap_folders"}
        for config in (absent, {**CONFIG, "imap_folders": ""}, {**CONFIG, "imap_folders": " , "}):
            with self.subTest(folders=config.get("imap_folders")):
                self.imap.commands.clear()
                self.run_sync(config=config)
                self.assertEqual(self.selected(), list(FOLDERS))

    def test_an_embed_refusal_skips_only_that_folder(self):
        calls = []

        def embed(texts, profile):
            calls.append(profile)
            if len(calls) == 1:
                raise ValueError("inference server refused the request (HTTP 413)")
            return embed_answer(texts, profile)

        with self.assertLogs("connectors.contrib.ai_model", "WARNING") as logs, \
                self.assertRaises(module.LabelSyncIncomplete) as caught:
            self.run_sync(embed=embed)
        self.assertEqual(str(caught.exception), f"embed refused for 1 folder(s): {PHISH!a}")
        self.assertIs(caught.exception.retryable, False)
        self.assertFalse(LabelRecord.objects.filter(label=PHISH).exists())
        self.assertFalse(LabelSyncState.objects.filter(folder=PHISH, last_uid__gt=0).exists())
        self.assertEqual(LabelSyncState.objects.get(folder=SPAM).last_uid, 11)
        self.assertIn("ValueError", "\n".join(logs.output))
        self.assertNotIn("413", "\n".join(logs.output))

    def test_changed_embed_versions_within_a_chunk_skip_the_folder(self):
        self.imap.folders[PHISH]["messages"] = {u: forward(u) for u in range(1, 41)}
        answers = iter(["legacy-first128", "legacy-first128", "other-recipe", "other-recipe"])

        def embed(texts, profile):
            return {**embed_answer(texts, profile), "preprocessing_version": next(answers)}

        with mock.patch.object(module, "CHUNK", 100), self.assertRaises(module.LabelSyncIncomplete):
            self.run_sync(config={**CONFIG, "imap_folders": PHISH}, embed=embed)
        self.assertFalse(LabelRecord.objects.exists())
        self.assertFalse(LabelSyncState.objects.filter(last_uid__gt=0).exists())

    def test_chunks_commit_one_by_one(self):
        self.imap.folders[PHISH]["messages"] = {u: forward(u) for u in range(1, 6)}
        with mock.patch.object(module, "CHUNK", 2):
            call, _ = self.run_sync(config={**CONFIG, "imap_folders": PHISH})
        self.assertEqual([len(c.args[0]) for c in call.call_args_list], [2, 2, 2, 2, 1, 1])
        self.assertEqual((LabelRecord.objects.count(), LabelSyncState.objects.get().last_uid), (5, 5))

    def test_a_failure_in_chunk_two_keeps_chunk_one(self):
        self.imap.folders[PHISH]["messages"] = {u: forward(u) for u in range(1, 4)}
        answers = [embed_answer, embed_answer, ProviderUnavailable("inference server HTTP 503")]

        def embed(texts, profile):
            step = answers.pop(0) if answers else embed_answer
            if isinstance(step, Exception):
                raise step
            return step(texts, profile)

        with mock.patch.object(module, "CHUNK", 2), self.assertRaises(ProviderUnavailable):
            self.run_sync(config={**CONFIG, "imap_folders": PHISH}, embed=embed)
        self.assertEqual(sorted(LabelRecord.objects.values_list("message_id", flat=True)),
                         ["id.1@evil.example", "id.2@evil.example"])
        self.assertEqual(LabelSyncState.objects.get().last_uid, 2)

    def test_a_failure_on_the_second_embed_batch_commits_nothing(self):
        self.imap.folders[PHISH]["messages"] = {u: forward(u) for u in range(1, 41)}
        answers = [embed_answer, embed_answer, ProviderUnavailable("inference server HTTP 503")]

        def embed(texts, profile):
            step = answers.pop(0) if answers else embed_answer
            if isinstance(step, Exception):
                raise step
            return step(texts, profile)

        with mock.patch.object(module, "CHUNK", 100), self.assertRaises(ProviderUnavailable):
            self.run_sync(config={**CONFIG, "imap_folders": PHISH}, embed=embed)
        self.assertFalse(LabelRecord.objects.exists())
        self.assertFalse(LabelSyncState.objects.filter(last_uid__gt=0).exists())

    def test_a_row_write_failure_rolls_back_rows_and_checkpoint(self):
        real = module.ledger.record_folder_observation
        calls = []

        def record(*args, **kw):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("db gone")
            return real(*args, **kw)

        with mock.patch.object(module.ledger, "record_folder_observation", side_effect=record), \
                self.assertRaises(RuntimeError):
            self.run_sync(config={**CONFIG, "imap_folders": PHISH})
        self.assertFalse(LabelRecord.objects.exists())
        self.assertFalse(LabelSyncState.objects.filter(last_uid__gt=0).exists())

    def test_the_time_budget_stops_the_run_after_a_committed_chunk(self):
        self.imap.folders[PHISH]["messages"] = {u: forward(u) for u in range(1, 6)}
        clock = iter([0.0, 0.0])  # sync start, before chunk 1; later calls are past the budget
        with mock.patch.object(module, "CHUNK", 2), \
                mock.patch.object(module, "monotonic", side_effect=lambda: next(clock, module.TIME_BUDGET_SECONDS)):
            self.run_sync()
        self.assertEqual((LabelRecord.objects.count(), LabelSyncState.objects.get(folder=PHISH).last_uid), (2, 2))
        self.assertFalse(LabelSyncState.objects.filter(folder=SPAM).exists())
        self.assertIn(("LOGOUT",), self.imap.commands)

    def test_inner_message_id_matches_a_case_through_sync(self):
        from django.contrib.auth import get_user_model
        from case_handler.models import Case, CaseHasFileOrMail
        from mail_feeder.models import Mail, MailHeader

        header = MailHeader.objects.create(header_value=str({"Message-ID": ["<ID.70@Evil.Example>"]}),
                                           fuzzy_hash="h")
        mail = Mail.objects.create(subject="s", reportedBy="r", to="t", mail_id="m", mail_header=header,
                                   date=datetime(2026, 10, 5, tzinfo=timezone.utc))
        case = Case.objects.create(description="", reporter=get_user_model().objects.create_user("u", password="x"))
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save(update_fields=["fileOrMail"])
        self.imap.folders[PHISH]["messages"] = {1: forward(60, attach=(inner(70),))}
        self.run_sync(config={**CONFIG, "imap_folders": PHISH})
        self.assertEqual(LabelRecord.objects.get().case, case)

    def test_a_row_value_error_is_not_reported_as_an_embed_refusal(self):
        with mock.patch.object(module.ledger, "record_folder_observation", side_effect=ValueError("row")), \
                self.assertRaises(ValueError) as caught:
            self.run_sync(config={**CONFIG, "imap_folders": PHISH})
        self.assertNotIsInstance(caught.exception, module.LabelSyncIncomplete)

    def test_the_budget_is_checked_between_embed_batches(self):
        self.assertEqual(module.TIME_BUDGET_SECONDS, 300)
        self.imap.folders[PHISH]["messages"] = {u: forward(u) for u in range(1, 41)}
        clock = iter([0.0, 0.0])  # sync start, before the chunk; before batch 2 the budget is spent
        with mock.patch.object(module, "monotonic", side_effect=lambda: next(clock, module.TIME_BUDGET_SECONDS)), \
                mock.patch.object(module, "CHUNK", 100):
            call, _ = self.run_sync()
        self.assertEqual([len(c.args[0]) for c in call.call_args_list], [32, 32])
        self.assertFalse(LabelRecord.objects.exists())
        self.assertFalse(LabelSyncState.objects.filter(last_uid__gt=0).exists())
        self.assertFalse(LabelSyncState.objects.filter(folder=SPAM).exists())

    def test_a_uidvalidity_reset_applies_once_across_chunks(self):
        self.run_sync(config={**CONFIG, "imap_folders": PHISH})
        self.imap.folders[PHISH] = {"uidvalidity": 8, "messages": {1: forward(1), 2: forward(5), 3: forward(6)}}
        with mock.patch.object(module, "CHUNK", 1):
            self.run_sync(config={**CONFIG, "imap_folders": PHISH})
        searches = [c[-1] for c in self.imap.commands if c[:2] == ("UID", "SEARCH")]
        self.assertEqual(searches[-4:], ["1:*", "2:*", "3:*", "4:*"])
        self.assertEqual(LabelRecord.objects.count(), 5)
        state = LabelSyncState.objects.get()
        self.assertEqual((state.uidvalidity, state.last_uid), (8, 3))


class FolderHierarchyTest(TestCase):
    """Fix wave 2: the class comes from the last hierarchy segment; nothing known fails the run."""

    def run_sync(self, imap, folders):
        with mock.patch.object(imap_sync, "connect", return_value=imap) as connect, \
                mock.patch.object(module.AiInferenceClient, "embed", side_effect=embed_answer):
            AiModelConnector({**CONFIG, "imap_folders": folders}).sync()
        return connect

    def test_hierarchical_names_are_read_and_stored_canonically(self):
        dotted, slashed = "INBOX.2_CLASSIC_PHISHING", "Review/0_LEGIT_EXTERNAL_COMMUNICATION"
        imap = FakeImap({
            dotted: {"uidvalidity": 7, "messages": {1: forward(1)}},
            slashed: {"uidvalidity": 3, "messages": {2: forward(2)}},
        })
        self.run_sync(imap, f"{dotted},{slashed}")
        selected = [c[1] for c in imap.commands if c[0] == "SELECT"]
        self.assertEqual(selected, [f'"{dotted}"', f'"{slashed}"'])
        rows = LabelRecord.objects.order_by("pk")
        self.assertEqual(
            [(r.label, r.label_class) for r in rows],
            [("2_CLASSIC_PHISHING", "Dangerous"), ("0_LEGIT_EXTERNAL_COMMUNICATION", "Safe")],
        )
        self.assertTrue(rows[0].source_ref.startswith(f"{dotted}:7:"))
        self.assertEqual(set(LabelSyncState.objects.values_list("folder", flat=True)), {dotted, slashed})
        self.run_sync(imap, f"{dotted},{slashed}")  # re-read: nothing new
        self.assertEqual(LabelRecord.objects.count(), 2)

    def test_only_unknown_folders_fail_the_run_without_a_retry(self):
        imap = FakeImap({"Inbox": {"uidvalidity": 1, "messages": {1: forward(1)}}})
        with self.assertRaises(module.LabelSyncIncomplete) as caught:
            connect = self.run_sync(imap, "Inbox, 9_ODD,Archive/\u00e9t\u00e9")
        self.assertIs(caught.exception.retryable, False)
        message = str(caught.exception)
        self.assertIn("3", message)
        self.assertIn("'Inbox'", message)
        self.assertIn(ascii("Archive/\u00e9t\u00e9"), message)
        self.assertFalse(LabelRecord.objects.exists())
        self.assertFalse([c for c in imap.commands if c[0] == "SELECT"])
