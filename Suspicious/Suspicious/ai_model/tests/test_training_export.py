"""Plan E, Task 8a: ledger rows in the training preprocessing, the re-embed command and the ledger
export the training job reads. The npz is checked with numpy here; the round trip through the
real training/dataset.py reader is Analyzers/AIMailAnalyzer/tests/test_ledger_export.py."""
import hashlib
import io
import json
from io import StringIO
from unittest import mock

import numpy as np
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase

from ai_model import export, ledger, registry, training_data
from ai_model.models import LabelRecord
from ai_model.taxonomy import FOLDERS
from ai_model.tests.test_label_sync import CONFIG, PHISH
from ai_model.tests.test_ledger import CaseMixin
from case_handler.models import Campaign, CampaignMember
from common.storage.fake import FakeObjectStore
from connectors.contrib.ai_model import connector as module
from connectors.contrib.ai_model import imap_sync
from connectors.contrib.ai_model.connector import AiModelConnector
from connectors.contrib.ai_model.tests.fake_imap import FakeImap
from connectors.contrib.ai_model.tests.test_imap_sync import forward

TP = "chunkmean-tokens-v1"


def make_row(n, folder=PHISH, *, case=None, pv=TP, status="active", trust="folder", dim=4,
             source="imap_folder", ref=None):
    return LabelRecord.objects.create(
        message_id=f"m{n}", message_id_hash=f"{n:064x}", case=case, source=source,
        source_ref=ref or f"{folder}:7:{n}", label=folder, label_class="Dangerous", trust=trust,
        embedding=json.dumps([float(n)] * dim), campaign_embedding=json.dumps([1.0, float(n)]),
        preprocessing_version=pv, embedding_version="cmp-e1", status=status)


def full_ledger(per_folder=8, start=0):
    """Every folder with per_folder rows: each head class has at least 8."""
    n = start
    for folder in FOLDERS:
        for _ in range(per_folder):
            n += 1
            make_row(n, folder)
    return n


class TrainingDataTest(SimpleTestCase):
    def rows(self, per_folder=8):
        return [(f, [1.0, 2.0], [3.0], i) for i, f in enumerate(f for f in FOLDERS for _ in range(per_folder))]

    def test_constants(self):
        self.assertEqual(training_data.TRAINING_PREPROCESSING, TP)
        self.assertEqual(set(training_data.HEAD_TARGETS["safe_suspicious"]), set(FOLDERS))

    def test_builds_the_four_arrays_with_the_reader_dtypes(self):
        rows = self.rows()
        rows[1] = (rows[1][0], rows[1][1], rows[1][2], None)
        rows[2] = (rows[2][0], rows[2][1], rows[2][2], 0)  # a second row of case 0
        with np.load(io.BytesIO(training_data.build_dataset(rows)), allow_pickle=False) as npz:
            self.assertEqual(sorted(npz.files), ["campaign_embeddings", "case_ids", "embeddings", "folders"])
            self.assertEqual(npz["embeddings"].dtype, np.float32)
            self.assertEqual(npz["embeddings"].shape, (64, 2))
            self.assertEqual(npz["campaign_embeddings"].shape, (64, 1))
            self.assertEqual(npz["folders"].dtype.kind, "U")
            self.assertEqual(npz["case_ids"].dtype, np.int64)
            self.assertEqual(npz["case_ids"][:4].tolist(), [0, -1, -1, 3])

    def test_refuses_a_short_head_class_naming_head_and_class(self):
        rows = [r for r in self.rows() if r[0] != "2_WHALING_PHISHING"]
        rows += [("2_WHALING_PHISHING", [1.0, 2.0], [3.0], 900 + i) for i in range(7)]
        with self.assertRaisesRegex(training_data.DatasetRefused,
                                    r"head dangerous class 3 \(2_WHALING_PHISHING\) has 7 rows, needs 8"):
            training_data.build_dataset(rows)

    def test_refuses_too_many_rows_ragged_and_non_finite(self):
        with mock.patch.object(training_data, "MAX_ROWS", 10), \
                self.assertRaisesRegex(training_data.DatasetRefused, "64 rows, at most 10"):
            training_data.build_dataset(self.rows())
        rows = self.rows()
        rows[0] = (rows[0][0], [1.0], [3.0], 0)
        with self.assertRaisesRegex(training_data.DatasetRefused, "embeddings"):
            training_data.build_dataset(rows)
        rows = self.rows()
        rows[0] = (rows[0][0], [float("nan"), 1.0], [3.0], 0)
        with self.assertRaisesRegex(training_data.DatasetRefused, "non-finite"):
            training_data.build_dataset(rows)

    def test_digest_is_order_free(self):
        a = training_data.digest([("h2", "1_SPAM"), ("h1", "2_CLONE_PHISHING")])
        self.assertEqual(a, training_data.digest([("h1", "2_CLONE_PHISHING"), ("h2", "1_SPAM")]))
        self.assertRegex(a, r"^[0-9a-f]{64}$")


class ReplaceEmbeddingTest(TestCase):
    def test_changes_only_embedding_and_version(self):
        row = make_row(1, pv="legacy-first128")
        before = LabelRecord.objects.filter(pk=row.pk).values().get()
        self.assertTrue(ledger.replace_embedding(row, [0.5, 0.25], TP))
        after = LabelRecord.objects.filter(pk=row.pk).values().get()
        self.assertEqual((json.loads(after["embedding"]), after["preprocessing_version"]), ([0.5, 0.25], TP))
        changed = {k for k in before if before[k] != after[k]}
        self.assertEqual(changed, {"embedding", "preprocessing_version"})

    def test_a_row_changed_meanwhile_is_not_overwritten(self):
        row = make_row(1, pv="legacy-first128")
        stale = LabelRecord.objects.get(pk=row.pk)
        self.assertTrue(ledger.replace_embedding(row, [0.5], TP))
        self.assertFalse(ledger.replace_embedding(stale, [0.9], TP))
        self.assertEqual(json.loads(LabelRecord.objects.get(pk=row.pk).embedding), [0.5])

    def test_save_still_refuses_embedding_and_other_changes(self):
        row = make_row(1, pv="legacy-first128")
        for field, value in (("embedding", "[0.1]"), ("preprocessing_version", TP), ("label", "1_SPAM"),
                             ("campaign_embedding", "[0.2]")):
            fresh = LabelRecord.objects.get(pk=row.pk)
            setattr(fresh, field, value)
            with self.assertRaises(ValueError):
                fresh.save()


class ExportTest(CaseMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.store = FakeObjectStore()
        patcher = mock.patch.object(registry, "get_store", return_value=self.store)
        patcher.start()
        self.addCleanup(patcher.stop)

    def load(self, result):
        data = self.store._data[(registry.DATASET_BUCKET, result.key)]
        return np.load(io.BytesIO(data), allow_pickle=False)

    def test_exports_active_folder_rows_only_and_uploads_with_a_presigned_get(self):
        n = full_ledger()
        case = self.make_case()
        make_row(n + 1, case=case)
        make_row(n + 2, status="superseded")
        make_row(n + 3, status="flagged")
        LabelRecord.objects.create(message_id="v", message_id_hash="v" * 64, case=case,
                                   source="analyst_verdict", label="Safe", label_class="Safe", trust="verdict")
        result = export.export_ledger("job-1")
        self.assertEqual(result.key, "job-1/dataset.npz")
        self.assertEqual(result.url, "fake://ai-datasets/job-1/dataset.npz?expires=900")
        self.assertEqual(result.rows, 65)
        with self.load(result) as npz:
            self.assertEqual(npz["embeddings"].shape, (65, 4))
            self.assertEqual(npz["case_ids"].tolist().count(case.pk), 1)
            self.assertEqual(npz["case_ids"].tolist().count(-1), 64)
            self.assertEqual(sorted(set(npz["folders"].tolist())), sorted(FOLDERS))
        # the digest is over the sorted (message_id_hash, label) pairs
        rows = LabelRecord.objects.filter(status="active", trust="folder")
        self.assertEqual(result.ledger_digest,
                         training_data.digest(rows.values_list("message_id_hash", "label")))

    def test_campaign_refs_and_digest(self):
        n = full_ledger()
        case = self.make_case()
        campaign = Campaign.objects.create()
        CampaignMember.objects.create(campaign=campaign, case=case)
        make_row(n + 1, case=case)
        result = export.export_ledger("job-2")
        self.assertEqual(result.campaign_refs, (campaign.ref,))
        self.assertEqual(result.campaign_refs_digest, training_data.digest([campaign.ref]))
        expected = hashlib.sha256(json.dumps(sorted([campaign.ref])).encode()).hexdigest()
        self.assertEqual(result.campaign_refs_digest, expected)

    def test_refuses_rows_in_another_preprocessing_naming_the_command(self):
        n = full_ledger()
        make_row(n + 1, pv="legacy-first128")
        with self.assertRaisesRegex(export.ExportRefused, "1 trainable row.*ai_model_reembed_ledger"):
            export.export_ledger("job-3")
        self.assertEqual(self.store.list_buckets(), [])

    def test_refuses_short_classes_and_too_many_rows(self):
        full_ledger(per_folder=7)
        with self.assertRaisesRegex(export.ExportRefused, r"head \w+ class \d \(.*\) has 7 rows, needs 8"):
            export.export_ledger("job-4")
        with mock.patch.object(training_data, "MAX_ROWS", 10), \
                self.assertRaisesRegex(export.ExportRefused, "56 rows, at most 10"):
            export.export_ledger("job-4")

    def test_refuses_a_bad_job_id(self):
        full_ledger()
        with self.assertRaises(registry.RegistryError):
            export.export_ledger("../x")


EMBED_CALLS = []


def embed(texts, profile, preprocessing="legacy-first128"):
    EMBED_CALLS.append((len(texts), profile, preprocessing))
    return {"vectors": [[0.5, float(len(t) > 0)] for t in texts], "preprocessing_version": preprocessing,
            "embedding_version": "cmp-e1"}


class ReembedCommandTest(TestCase):
    CMD = "ai_model_reembed_ledger"

    def setUp(self):
        EMBED_CALLS.clear()
        patcher = mock.patch("ai_model.ledger.enabled", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.imap = FakeImap({PHISH: {"uidvalidity": 7, "messages": {u: forward(u) for u in range(1, 41)}}})

    def run_cmd(self, *args, embed=embed):
        out = StringIO()
        with mock.patch("connectors.registry.registry.instantiate", return_value=AiModelConnector(CONFIG)), \
                mock.patch.object(imap_sync, "connect", return_value=self.imap), \
                mock.patch.object(module.AiInferenceClient, "embed", side_effect=embed):
            call_command(self.CMD, *args, stdout=out)
        return out.getvalue()

    def test_reembeds_stale_rows_in_batches_of_32_and_counts_skips(self):
        for uid in range(1, 36):
            make_row(uid, pv="legacy-first128")
        make_row(50, pv="legacy-first128")                                   # gone from the folder
        make_row(51, pv="legacy-first128", ref=f"{PHISH}:99:2")              # UIDVALIDITY changed
        make_row(52, pv="legacy-first128", ref="garbage")                    # bad locator
        make_row(53, pv="legacy-first128", status="superseded")              # not trainable
        fresh = make_row(54, pv=TP, ref=f"{PHISH}:7:36")                     # already current
        out = self.run_cmd()
        self.assertEqual(EMBED_CALLS, [(32, "classifier", TP), (3, "classifier", TP)])
        self.assertIn("re-embedded: 35", out)
        self.assertIn("gone 1", out)
        self.assertIn("UIDVALIDITY changed 1", out)
        self.assertIn("bad locator 1", out)
        stale = LabelRecord.objects.exclude(preprocessing_version=TP).values_list("message_id", flat=True)
        self.assertEqual(sorted(stale), ["m50", "m51", "m52", "m53"])
        self.assertEqual(json.loads(LabelRecord.objects.get(message_id="m1").embedding), [0.5, 1.0])
        self.assertEqual(LabelRecord.objects.get(pk=fresh.pk).embedding, json.dumps([54.0] * 4))
        for secret in ("Urgent", "evil.example", "analyst", "reviewer", "imap-pa55"):
            self.assertNotIn(secret, out)

    def test_dry_run_counts_only(self):
        make_row(1, pv="legacy-first128")
        out = self.run_cmd("--dry-run")
        self.assertIn("to re-embed: 1", out)
        self.assertEqual(EMBED_CALLS, [])
        self.assertEqual(self.imap.commands, [])
        self.assertFalse(LabelRecord.objects.filter(preprocessing_version=TP).exists())

    def test_limit(self):
        for uid in range(1, 4):
            make_row(uid, pv="legacy-first128")
        self.assertIn("re-embedded: 2", self.run_cmd("--limit", "2"))
        self.assertIn("re-embedded: 1", self.run_cmd())

    def test_a_server_answering_another_preprocessing_writes_nothing(self):
        make_row(1, pv="legacy-first128")

        def old_server(texts, profile, preprocessing=None):
            return embed(texts, profile)  # ignores the field: legacy-first128

        with self.assertRaisesRegex(CommandError, "legacy-first128"):
            self.run_cmd(embed=old_server)
        self.assertFalse(LabelRecord.objects.filter(preprocessing_version=TP).exists())

    def test_refuses_when_disabled_and_reports_error_class_only(self):
        make_row(1, pv="legacy-first128")
        with mock.patch("ai_model.ledger.enabled", return_value=False), self.assertRaises(CommandError):
            self.run_cmd()
        with mock.patch.object(imap_sync, "connect", side_effect=imap_sync.ImapLoginFailed("imap-pa55")), \
                mock.patch("connectors.registry.registry.instantiate", return_value=AiModelConnector(CONFIG)), \
                self.assertRaises(CommandError) as caught:
            call_command(self.CMD, stdout=StringIO())
        self.assertEqual(str(caught.exception), "ImapLoginFailed")
