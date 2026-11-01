"""ai_model_backfill_labels: verdict and proposal rows for existing cases, and the review-folder
sync without its per-run cap (Plan D, Task 7)."""
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError

from django.test import TestCase

from ai_model import ledger
from ai_model.messageid import message_id_hash
from ai_model.models import LabelRecord
from case_handler.models import Case
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
        self.user.username, self.user.email = "zelda.quux", "zelda.quux@meridian.example"
        self.user.save()
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
        self.assertNotIn(self.user.username, out)
        self.assertNotIn(self.user.email, out)

    def test_non_label_results_are_skipped_and_source_ref_names_the_user(self):
        for i, result in enumerate(("Unchallenged", "AllowListed")):
            self.make_case(f"<n{i}@x>", results=result, last_update_by=self.user)
        self.run_command()
        self.assertEqual(LabelRecord.objects.filter(source="analyst_verdict").count(), 1)
        self.assertEqual(LabelRecord.objects.get(source="analyst_verdict").source_ref, f"user:{self.user.pk}")

    def test_a_changed_proposal_supersedes_and_an_identical_one_is_skipped(self):
        self.run_command()
        Case.objects.filter(pk=self.challenged.pk).update(challenge_proposed_result="Dangerous")
        self.run_command()
        self.run_command()
        rows = LabelRecord.objects.filter(source="challenge", case=self.challenged)
        self.assertEqual(rows.count(), 2)
        self.assertEqual(rows.get(status="active").label_class, "Dangerous")

    def test_folders_dry_run_leaves_imap_untouched(self):
        connector = AiModelConnector(CONFIG)
        with mock.patch("connectors.registry.registry.instantiate", return_value=connector), \
                mock.patch.object(imap_sync, "connect") as connect:
            self.run_command("--folders", "--dry-run")
        connect.assert_not_called()

    def test_folders_dry_run_refuses_without_an_imap_host(self):
        with mock.patch("connectors.registry.registry.instantiate",
                        return_value=AiModelConnector({**CONFIG, "imap_host": ""})):
            with self.assertRaises(CommandError):
                self.run_command("--folders", "--dry-run")

    def test_folder_sync_failures_become_command_errors_with_the_class_only(self):
        connector = AiModelConnector(CONFIG)
        for exc in (imap_sync.ImapLoginFailed("pw imap-pa55"), imap_sync.ImapConnectionLost("reviewer"),
                    imap_sync.ImapTlsFailed("SSLCertVerificationError")):
            with mock.patch("connectors.registry.registry.instantiate", return_value=connector), \
                    mock.patch.object(imap_sync, "connect", side_effect=exc):
                with self.assertRaises(CommandError) as caught:
                    self.run_command("--folders")
            self.assertEqual(str(caught.exception), type(exc).__name__)

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
        self.assertIn("7 folder row", out)
        with mock.patch("connectors.registry.registry.instantiate", return_value=connector), \
                mock.patch.object(imap_sync, "connect", return_value=imap), \
                mock.patch.object(module.AiInferenceClient, "embed", side_effect=embed_answer):
            self.assertIn("0 folder row", self.run_command("--folders"))
        self.assertEqual(LabelRecord.objects.filter(source="imap_folder").count(), 7)


class BackfillHistoryTest(CaseMixin, TestCase):
    """The backfill must not rewrite history (fix wave 1) and re-matches unmatched folder rows (4)."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch("ai_model.ledger.enabled", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_command(self, *args):
        out = StringIO()
        call_command(COMMAND, *args, stdout=out)
        return out.getvalue()

    def test_a_redone_case_keeps_the_analyst_verdict(self):
        # The analyst said Dangerous (live row); "Redo analysis" re-scored the case to Safe, and
        # last_update_by still names the analyst. The backfill must not record Safe under them.
        case = self.make_case(results="Dangerous", last_update_by=self.user)
        ledger.record_verdict(case, self.user, "Dangerous")
        Case.objects.filter(pk=case.pk).update(results="Safe")
        self.assertIn("0 verdict", self.run_command())
        rows = LabelRecord.objects.filter(source="analyst_verdict", case=case)
        self.assertEqual(list(rows.values_list("label_class", "status")), [("Dangerous", "active")])

    def test_a_case_with_only_a_superseded_verdict_row_is_skipped(self):
        case = self.make_case(results="Safe", last_update_by=self.user)
        ledger.record_verdict(case, self.user, "Safe")
        LabelRecord.objects.filter(case=case).update(status="superseded")
        self.assertIn("0 verdict", self.run_command())
        self.assertEqual(LabelRecord.objects.filter(case=case).count(), 1)

    def test_backfilled_verdict_is_observed_at_the_case_last_update(self):
        case = self.make_case(results="Dangerous", last_update_by=self.user)
        self.run_command()
        row = LabelRecord.objects.get(source="analyst_verdict", case=case)
        self.assertEqual(row.observed_at, Case.objects.get(pk=case.pk).last_update)

    def _folder_row(self, message_id):
        return LabelRecord.objects.create(
            message_id=message_id, message_id_hash=message_id_hash(message_id or "x"),
            source="imap_folder", label="2_CLASSIC_PHISHING", label_class="Dangerous", trust="folder",
        )

    def test_unmatched_folder_rows_are_matched_late(self):
        case = self.make_case("<late@x.example>")
        late = self._folder_row("late@x.example")
        nobody = self._folder_row("nobody@x.example")
        no_id = self._folder_row("")
        self.assertIn("would re-match 1 folder row", self.run_command("--dry-run"))
        self.assertIsNone(LabelRecord.objects.get(pk=late.pk).case)
        self.assertIn("re-matched 1 folder row", self.run_command())
        self.assertEqual(LabelRecord.objects.get(pk=late.pk).case, case)
        self.assertIsNone(LabelRecord.objects.get(pk=nobody.pk).case)
        self.assertIsNone(LabelRecord.objects.get(pk=no_id.pk).case)
        self.assertIn("re-matched 0 folder row", self.run_command())
