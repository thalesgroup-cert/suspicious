"""Ruling F8: seeding the shadow's classes for the mails already in the live collection."""
from unittest import mock

from django.test import TestCase

from ai_model import registry, tasks
from ai_model.models import ShadowResult
from ai_model.tests.test_registry import cand
from ai_model.tests.test_shadow_result import answer
from connectors.contrib.ai_model.tests.test_campaigns import _case

SECRET = "mail text never logged"


class PagedCollection:
    def __init__(self, ids):
        self.ids, self.pages = ids, []

    def get(self, limit, offset, include):
        self.pages.append((offset, limit))
        ids = self.ids[offset:offset + limit]
        return {"ids": ids, "documents": [f"{SECRET} {i}" for i in ids], "metadatas": [{} for _ in ids]}


class FakeClient:
    def __init__(self):
        self.calls = []

    def classify(self, text, exclude_case_ids=None, versions=("active",)):
        self.calls.append((text, tuple(versions)))
        return {"results": {"shadow": answer("s1", "DANGEROUS")}}


class SeedShadowTest(TestCase):
    def setUp(self):
        self.version = registry.set_shadow(cand("s1", manifest={"eligible": True}))
        self.cases = [_case() for _ in range(30)]
        ids = [f"case-{c.id}" for c in self.cases] + ["case-999999", "2611-abc"]
        self.coll, self.client = PagedCollection(ids), FakeClient()
        chroma = mock.MagicMock()
        chroma.get_or_create_collection.return_value = self.coll
        connector = mock.MagicMock()
        connector._client.return_value = self.client
        for patcher in (
            mock.patch("ai_model.ledger.enabled", return_value=True),
            mock.patch("connectors.registry.registry.instantiate", return_value=connector),
            mock.patch("ai_model.serversync.sync", return_value=True),
            mock.patch("connectors.contrib.ai_model.campaigns.get_chroma_client", return_value=chroma),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def seed(self, offset=0):
        with mock.patch.object(tasks.seed_shadow, "apply_async") as requeue:
            tasks.seed_shadow("s1", offset)
        return requeue

    def test_pages_the_collection_and_stores_seed_rows_for_existing_cases(self):
        requeue = self.seed()
        requeue.assert_not_called()
        self.assertEqual(self.coll.pages, [(0, 25), (25, 25)])
        self.assertEqual({v for _, v in self.client.calls}, {("shadow",)})
        rows = ShadowResult.objects.filter(version=self.version)
        self.assertEqual(set(rows.values_list("case_id", flat=True)), {c.id for c in self.cases})
        self.assertEqual(set(rows.values_list("origin", "result", "would_be_result")),
                         {("seed", "DANGEROUS", "")})

    def test_a_spent_budget_requeues_with_the_new_offset(self):
        with mock.patch.object(tasks, "monotonic", side_effect=[0, 0, tasks.SEED_BUDGET_SECONDS]):
            requeue = self.seed()
        requeue.assert_called_once_with(("s1", 25))
        self.assertEqual(ShadowResult.objects.count(), 25)

    def test_a_rerun_classifies_nothing_again_and_keeps_live_rows(self):
        live = ShadowResult.objects.create(case=self.cases[0], version=self.version, result="SAFE",
                                           score=1, confidence=90, would_be_result="Safe")
        self.seed()
        calls = len(self.client.calls)
        self.assertEqual(calls, 29)
        self.seed()
        self.assertEqual(len(self.client.calls), calls)
        live.refresh_from_db()
        self.assertEqual((live.origin, live.result, live.would_be_result), ("live", "SAFE", "Safe"))

    def test_a_version_that_is_no_longer_the_shadow_does_nothing(self):
        registry.discard(self.version)
        requeue = self.seed()
        requeue.assert_not_called()
        self.assertEqual((self.coll.pages, self.client.calls), ([], []))

    def test_a_refused_mail_is_skipped_and_its_text_not_logged(self):
        self.client.classify = mock.Mock(side_effect=ValueError(f"HTTP 422 {SECRET}"))
        with self.assertLogs("ai_model.tasks", "WARNING") as logs:
            self.seed()
        self.assertFalse(ShadowResult.objects.exists())
        self.assertNotIn(SECRET, "\n".join(logs.output))

    def test_set_shadow_queues_the_seeding_after_commit(self):
        with mock.patch.object(tasks.seed_shadow, "delay") as delay, \
                self.captureOnCommitCallbacks(execute=True):
            registry.discard(self.version)
            registry.set_shadow(cand("s2", manifest={"eligible": True}))
        delay.assert_called_once_with("s2")
