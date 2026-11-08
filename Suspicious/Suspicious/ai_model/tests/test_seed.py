"""Ruling F8: seeding the shadow's classes for the mails already in the live collection."""
from unittest import mock

from celery.exceptions import SoftTimeLimitExceeded
from django.test import TestCase

from ai_model import registry, tasks
from ai_model.models import ShadowResult
from ai_model.tests.test_registry import cand
from ai_model.tests.test_shadow_result import answer
from connectors.contrib.ai_model.client import ShadowNotLoaded
from connectors.providers import ProviderUnavailable
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
        self.calls, self.excluded = [], []

    def classify(self, text, exclude_case_ids=None, versions=("active",)):
        self.calls.append((text, tuple(versions)))
        self.excluded.append(exclude_case_ids)
        return {"results": {"shadow": answer("s1", "DANGEROUS")}}


class SeedShadowTest(TestCase):
    def setUp(self):
        self.version = registry.set_shadow(cand("s1", manifest={"eligible": True}))
        self.cases = [_case() for _ in range(30)]
        ids = [f"case-{c.id}" for c in self.cases] + ["case-999999", "2611-abc"]
        self.coll, self.client = PagedCollection(ids), FakeClient()
        self.chroma = chroma = mock.MagicMock()
        chroma.get_or_create_collection.return_value = self.coll
        connector = mock.MagicMock()
        connector._client.return_value = self.client
        for patcher in (
            mock.patch("ai_model.ledger.enabled", return_value=True),
            mock.patch("connectors.registry.registry.instantiate", return_value=connector),
            mock.patch("ai_model.serversync.sync", return_value=True),
            mock.patch("connectors.contrib.ai_model.campaigns.get_chroma_client", return_value=chroma),
            mock.patch.object(tasks, "SEED_PAUSE_SECONDS", 0),
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

    def test_each_case_is_left_out_of_its_own_neighbour_vote(self):
        self.seed()
        self.assertEqual(self.client.excluded, [[c.id] for c in self.cases])

    def test_pauses_after_each_classify_so_live_shadows_get_the_slot(self):
        with mock.patch.object(tasks, "SEED_PAUSE_SECONDS", 1), mock.patch.object(tasks, "sleep") as sleep:
            self.seed()
        self.assertEqual(sleep.call_args_list, [mock.call(1)] * len(self.client.calls))
        self.assertEqual(len(self.client.calls), 30)

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

    def paused_at(self, requeue, offset):
        requeue.assert_called_once_with(("s1", offset), countdown=tasks.SEED_RETRY_SECONDS)

    def test_a_live_row_written_during_the_classify_is_kept(self):
        def racing(text, exclude_case_ids=None, versions=("active",)):
            if not ShadowResult.objects.exists():  # the live path stores the first case meanwhile
                ShadowResult.objects.create(case=self.cases[0], version=self.version, result="SAFE",
                                            score=1, confidence=90, would_be_result="Safe")
            return {"results": {"shadow": answer("s1", "DANGEROUS")}}

        self.client.classify = racing
        self.seed()
        live = ShadowResult.objects.get(case=self.cases[0])
        self.assertEqual((live.origin, live.result, live.would_be_result), ("live", "SAFE", "Safe"))
        self.assertEqual(ShadowResult.objects.filter(origin="seed").count(), 29)

    def test_a_chroma_error_while_paging_pauses_at_the_same_offset(self):
        self.coll.get = mock.Mock(side_effect=ConnectionError(SECRET))
        with self.assertLogs("ai_model.tasks", "WARNING") as logs:
            requeue = self.seed(25)
        self.paused_at(requeue, 25)
        self.assertNotIn(SECRET, "\n".join(logs.output))

    def test_a_collection_that_cannot_be_opened_pauses(self):
        self.chroma.get_or_create_collection.side_effect = ConnectionError(SECRET)
        self.paused_at(self.seed(), 0)

    def test_a_retryable_server_failure_pauses_at_the_chunk_start(self):
        self.client.classify = mock.Mock(side_effect=ProviderUnavailable("HTTP 503"))
        self.paused_at(self.seed(), 0)

    def test_a_shadow_unloaded_on_the_server_pauses_instead_of_skipping(self):
        self.client.classify = mock.Mock(side_effect=ShadowNotLoaded("HTTP 409"))
        requeue = self.seed()
        self.paused_at(requeue, 0)
        self.assertEqual(self.client.classify.call_count, 1)

    def test_a_non_retryable_failure_skips_the_mail_not_the_run(self):
        self.client.classify = mock.Mock(side_effect=ProviderUnavailable("HTTP 401", retryable=False))
        with self.assertLogs("ai_model.tasks", "WARNING") as logs:
            requeue = self.seed()
        requeue.assert_not_called()
        self.assertEqual(self.client.classify.call_count, 30)
        self.assertIn("ProviderUnavailable", "\n".join(logs.output))

    def test_the_soft_time_limit_requeues_at_the_current_offset(self):
        calls = []

        def slow(text, exclude_case_ids=None, versions=("active",)):
            calls.append(text)
            if len(calls) == 27:
                raise SoftTimeLimitExceeded()
            return {"results": {"shadow": answer("s1", "DANGEROUS")}}

        self.client.classify = slow
        requeue = self.seed()
        requeue.assert_called_once_with(("s1", 25))

    def test_a_discard_between_chunks_stops_the_run(self):
        def discard_then_answer(text, exclude_case_ids=None, versions=("active",)):
            self.version.refresh_from_db()
            if self.version.status == "shadow":
                registry.discard(self.version)
            return {"results": {"shadow": answer("s1", "DANGEROUS")}}

        self.client.classify = discard_then_answer
        requeue = self.seed()
        requeue.assert_not_called()
        self.assertEqual(self.coll.pages, [(0, 25)])
