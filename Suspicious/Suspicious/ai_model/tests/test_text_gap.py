"""ai_model_text_gap: read-only live-vs-filed text similarity report (Plan E, Task 1)."""
from io import StringIO
import imaplib
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError
from django.test import TestCase

from ai_model.models import LabelRecord
from ai_model.tests.test_label_sync import CONFIG, PHISH
from ai_model.tests.test_ledger import CaseMixin
from connectors.contrib.ai_model import imap_sync
from connectors.contrib.ai_model import connector as module
from connectors.contrib.ai_model.connector import AiModelConnector
from connectors.contrib.ai_model.tests.fake_imap import FakeImap
from connectors.contrib.ai_model.tests.test_imap_sync import forward

CMD = "ai_model_text_gap"


def embed(texts, profile):
    # live text embeds to [1, 0]; any filed text to [1, 1]: cosine 0.7071
    return {"vectors": [[1.0, 0.0] if t.startswith("live") else [1.0, 1.0] for t in texts]}


class TextGapTest(CaseMixin, TestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch("ai_model.ledger.enabled", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.imap = FakeImap({PHISH: {"uidvalidity": 7, "messages": {1: forward(1), 2: forward(2)}}})
        self.case = self.make_case()
        self.row(self.case, 1)

    def row(self, case, uid, validity=7, ref=None, label_class="Dangerous"):
        return LabelRecord.objects.create(
            message_id=f"m{uid}", message_id_hash=f"h{uid}", case=case, source="imap_folder",
            source_ref=ref or f"{PHISH}:{validity}:{uid}", label=PHISH, label_class=label_class, trust="folder")

    def run_cmd(self, *args, body="live secret body", config=CONFIG):
        out = StringIO()
        with mock.patch("connectors.registry.registry.instantiate", return_value=AiModelConnector(config)), \
                mock.patch.object(imap_sync, "connect", return_value=self.imap), \
                mock.patch.object(module.AiInferenceClient, "embed", side_effect=embed), \
                mock.patch(f"ai_model.management.commands.{CMD}.mail_archive_for", return_value=object()), \
                mock.patch(f"ai_model.management.commands.{CMD}.read_archive_body", return_value=body):
            call_command(CMD, *args, stdout=out)
        return out.getvalue()

    def test_reports_statistics_without_mail_data_and_writes_nothing(self):
        before = list(LabelRecord.objects.values())
        out = self.run_cmd()
        self.assertIn("compared: 1", out)
        self.assertIn("median 0.7071", out)
        self.assertIn("Dangerous: median 0.7071", out)
        for secret in ("live secret body", "Urgent", "evil.example", "analyst", "reviewer"):
            self.assertNotIn(secret, out)
        self.assertEqual(list(LabelRecord.objects.values()), before)

    def test_skips_are_counted_by_reason(self):
        self.row(self.make_case("<2@x>"), 2, validity=99)             # UIDVALIDITY mismatch
        self.row(self.make_case("<3@x>"), 3)                          # uid not in the folder
        self.row(self.make_case("<4@x>"), 4, ref="garbage")           # no locator
        out = self.run_cmd()
        self.assertIn("UIDVALIDITY mismatch 1", out)
        self.assertIn("fetch failed 1", out)
        self.assertIn("bad locator 1", out)
        self.assertIn("compared: 1", out)
        self.assertIn("no archive 0", out)
        self.assertIn("no archive 4", self.run_cmd(body=""))

    def test_limit_bounds_the_work(self):
        self.row(self.make_case("<2@x>"), 2)
        self.assertIn("compared: 1", self.run_cmd("--limit", "1"))
        self.assertIn("compared: 2", self.run_cmd())

    def test_refusals_and_error_class_only(self):
        with mock.patch("ai_model.ledger.enabled", return_value=False), self.assertRaises(CommandError):
            self.run_cmd()
        with self.assertRaises(CommandError):
            self.run_cmd(config={**CONFIG, "imap_host": ""})
        with mock.patch.object(imap_sync, "connect", side_effect=imap_sync.ImapLoginFailed("imap-pa55")):
            with mock.patch("connectors.registry.registry.instantiate", return_value=AiModelConnector(CONFIG)), \
                    mock.patch(f"ai_model.management.commands.{CMD}.mail_archive_for", return_value=object()), \
                    mock.patch(f"ai_model.management.commands.{CMD}.read_archive_body", return_value="x"):
                with self.assertRaises(CommandError) as caught:
                    call_command(CMD, stdout=StringIO())
        self.assertEqual(str(caught.exception), "ImapLoginFailed")

    def test_connect_and_db_failures_become_class_only_command_errors(self):
        for exc in (OSError("imap-pa55 host"), imaplib.IMAP4.error("reviewer"), imaplib.IMAP4.abort("x"),
                    imap_sync.ImapTlsFailed("SSLError")):
            with mock.patch.object(imap_sync, "connect", side_effect=exc), \
                    mock.patch("connectors.registry.registry.instantiate", return_value=AiModelConnector(CONFIG)), \
                    mock.patch(f"ai_model.management.commands.{CMD}.mail_archive_for", return_value=object()), \
                    mock.patch(f"ai_model.management.commands.{CMD}.read_archive_body", return_value="x"):
                with self.assertRaises(CommandError) as caught:
                    call_command(CMD, stdout=StringIO())
            self.assertEqual(str(caught.exception), type(exc).__name__)
        with mock.patch("connectors.registry.registry.instantiate", return_value=AiModelConnector(CONFIG)), \
                mock.patch.object(LabelRecord.objects, "filter", side_effect=DatabaseError("secret sql")):
            with self.assertRaises(CommandError) as caught:
                call_command(CMD, stdout=StringIO())
        self.assertEqual(str(caught.exception), "DatabaseError")

    def test_invalid_imap_port_is_refused(self):
        for port in ("abc", 0, 70000, -1):
            with self.assertRaises(CommandError) as caught:
                self.run_cmd(config={**CONFIG, "imap_port": port})
            self.assertEqual(str(caught.exception), "invalid imap_port")


class StatisticsTest(CaseMixin, TestCase):
    """Hand-computed figures: live vector [1, 0], filed vector [c, sqrt(1 - c^2)], so cosine == c."""
    DANGEROUS = (0.1, 0.3, 0.5, 0.7)   # median 0.4
    SAFE = (0.8, 0.9, 1.0)             # median 0.9
    # all 7 sorted: .1 .3 .5 .7 .8 .9 1.0 -> median 0.7, p5 = .1 + .2*.3 = 0.16, p95 = .9 + .1*.7 = 0.97

    def setUp(self):
        super().setUp()
        patcher = mock.patch("ai_model.ledger.enabled", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.calls, self.vectors, self.n = [], {}, 0

    def add(self, cosine, label_class, zero_filed=False, zero_live=False):
        self.n += 1
        n = self.n
        case = self.make_case(f"<s{n}@x>")
        LabelRecord.objects.create(
            message_id=f"m{n}", message_id_hash=f"h{n}", case=case, source="imap_folder",
            source_ref=f"{PHISH}:7:{n}", label=PHISH, label_class=label_class, trust="folder")
        self.vectors[f"live{n}"] = [0.0, 0.0] if zero_live else [1.0, 0.0]
        self.vectors[f"f{n}"] = [0.0, 0.0] if zero_filed else [cosine, (1 - cosine ** 2) ** 0.5]

    def embed(self, texts, profile):
        self.calls.append((len(texts), profile))
        return {"vectors": [self.vectors[t] for t in texts]}

    def run_cmd(self):
        imap = FakeImap({PHISH: {"uidvalidity": 7, "messages": {u: forward(u, body=f"f{u}") for u in range(1, self.n + 1)}}})
        out = StringIO()
        with mock.patch("connectors.registry.registry.instantiate", return_value=AiModelConnector(CONFIG)), \
                mock.patch.object(imap_sync, "connect", return_value=imap), \
                mock.patch.object(module.AiInferenceClient, "embed", side_effect=self.embed), \
                mock.patch(f"ai_model.management.commands.{CMD}.mail_archive_for", side_effect=lambda c: c), \
                mock.patch(f"ai_model.management.commands.{CMD}.read_archive_body",
                           side_effect=lambda c: f"live{LabelRecord.objects.get(case=c).source_ref.rsplit(':', 1)[1]}"):
            call_command(CMD, "--limit", "100", stdout=out)
        return out.getvalue()

    def test_median_percentiles_and_per_class_medians(self):
        for c in self.DANGEROUS:
            self.add(c, "Dangerous")
        for c in self.SAFE:
            self.add(c, "Safe")
        out = self.run_cmd()
        self.assertIn("compared: 7", out)
        self.assertIn("cosine median 0.7000 p5 0.1600 p95 0.9700", out)
        self.assertIn("Dangerous: median 0.4000", out)
        self.assertIn("Safe: median 0.9000", out)

    def test_a_zero_vector_pair_is_skipped_and_kept_out_of_the_statistics(self):
        self.add(0.5, "Dangerous")
        self.add(0.9, "Dangerous", zero_filed=True)
        self.add(0.9, "Dangerous", zero_live=True)
        out = self.run_cmd()
        self.assertIn("compared: 1", out)
        self.assertIn("zero vector 2", out)
        self.assertIn("cosine median 0.5000 p5 0.5000 p95 0.5000", out)

    def test_embeds_in_batches_of_32_with_the_classifier_profile(self):
        for _ in range(33):
            self.add(0.5, "Dangerous")
        self.assertIn("compared: 33", self.run_cmd())
        self.assertEqual(self.calls, [(32, "classifier"), (32, "classifier"), (1, "classifier"), (1, "classifier")])
