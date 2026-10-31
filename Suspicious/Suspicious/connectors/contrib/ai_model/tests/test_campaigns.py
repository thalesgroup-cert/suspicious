import base64
import dataclasses
import json
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connection, transaction
from django.test import TestCase

from ai_model.campaign_profile import current_profile
from ai_model.models import AiAssessment
from case_handler.models import Campaign, CampaignMember, Case
from connectors.contrib.ai_model import campaigns
from connectors.contrib.ai_model.campaigns import CampaignStoreUnavailable
from connectors.contrib.ai_model.mailtext import header_dict
from connectors.models import ConnectorState

C = "connectors.contrib.ai_model.campaigns"
TEXT = "pay now"
HEADERS = {"Subject": ["Verify payroll"], "From": ["a@evil.example"]}


def _case():
    user, _ = get_user_model().objects.get_or_create(username="rep", defaults={"email": "r@e.c"})
    return Case.objects.create(reporter=user, description="t")


def _assessment(case, result="DANGEROUS", embedding=str([0.1, 0.2])):
    return AiAssessment.objects.create(
        case=case, model_version="m1", result=result, sub_class="phishing",
        score=9, confidence=90, campaign_embedding=embedding,
    )


class FakeCollection:
    """Every stored mail of the queried class is a neighbour at distance 0.1."""

    def __init__(self):
        self.docs = {}

    def get(self, ids=None, include=None):
        ids = [i for i in (ids or []) if i in self.docs]
        return {"ids": ids, "metadatas": [self.docs[i] for i in ids]}

    def add(self, ids, metadatas, **kw):
        self.docs[ids] = dict(metadatas[0])

    def update(self, ids, metadatas):
        ids = [ids] if isinstance(ids, str) else ids
        metas = [metadatas] if isinstance(metadatas, dict) else metadatas
        for i, m in zip(ids, metas):
            self.docs[i] = dict(m)

    def query(self, query_embeddings, where, n_results, include):
        hits = [(i, m) for i, m in self.docs.items()
                if m.get("classification") == where["classification"]][:n_results]
        return {"ids": [[i for i, _ in hits]], "metadatas": [[m for _, m in hits]],
                "documents": [["" for _ in hits]], "embeddings": [[[0] for _ in hits]],
                "distances": [[0.1 for _ in hits]]}


class DetectionTest(TestCase):
    def setUp(self):
        cache.delete("campaign:detect")
        self.coll = FakeCollection()
        self.profile = current_profile()

    def _seed(self, cases, headers=HEADERS):
        """Dangerous mails already in the collection, in no campaign."""
        for c in cases:
            self.coll.docs[f"case-{c.id}"] = {
                "suspicious_case_id": str(c.id), "classification": "DANGEROUS",
                "headers": str(headers), "sourceRefs": '[""]',
            }

    def _detect(self, case, result="DANGEROUS", embedding=str([0.1, 0.2]), headers=HEADERS, profile=None):
        return campaigns.detect_campaign(
            case, _assessment(case, result, embedding), TEXT, headers, profile or self.profile, self.coll
        )

    def test_a_non_dangerous_assessment_is_stored_not_a_campaign(self):
        self._seed([_case() for _ in range(3)])
        case = _case()
        self.assertIsNone(self._detect(case, result="SAFE"))
        self.assertEqual(Campaign.objects.count(), 0)
        doc = self.coll.docs[f"case-{case.id}"]
        self.assertEqual(doc["classification"], "SAFE")
        self.assertEqual(doc["embedding_version"], "cmp-e1")
        self.assertEqual(doc["confidence"], "0.9")

    def test_too_few_similar_mails_is_not_a_campaign(self):
        self._seed([_case(), _case()])
        case = _case()
        self.assertIsNone(self._detect(case))
        self.assertEqual(Campaign.objects.count(), 0)
        self.assertIn(f"case-{case.id}", self.coll.docs)

    def test_three_similar_mails_create_a_campaign_with_all_members(self):
        old = [_case() for _ in range(3)]
        self._seed(old)
        case = _case()
        campaign = self._detect(case)
        self.assertIsNotNone(campaign)
        self.assertEqual(campaign.title, "Verify payroll")
        self.assertEqual(set(campaign.members.values_list("case_id", flat=True)),
                         {c.id for c in old} | {case.id})
        # the Campaigns page groups ChromaDB documents by sourceRefs
        for c in old + [case]:
            self.assertEqual(json.loads(self.coll.docs[f"case-{c.id}"]["sourceRefs"]), [campaign.ref])

    def test_similar_mails_of_an_existing_campaign_join_it(self):
        old = [_case() for _ in range(3)]
        self._seed(old)
        campaign = Campaign.objects.create(title="x")
        for c in old:
            CampaignMember.objects.create(campaign=campaign, case=c)
        case = _case()
        self.assertEqual(self._detect(case), campaign)
        self.assertEqual(Campaign.objects.count(), 1)
        self.assertEqual(campaign.members.count(), 4)

    def test_the_second_sibling_joins_the_campaign_the_first_created(self):
        self._seed([_case() for _ in range(3)])
        created = self._detect(_case())
        self.assertIsNotNone(created)
        self.assertEqual(self._detect(_case()), created)
        self.assertEqual(Campaign.objects.count(), 1)
        self.assertEqual(created.members.count(), 5)

    def test_the_profile_thresholds_decide(self):
        self._seed([_case(), _case()])
        profile = dataclasses.replace(self.profile, min_members=2)
        self.assertIsNotNone(self._detect(_case(), profile=profile))

    def test_a_case_already_in_a_campaign_is_stored_tagged_and_returned(self):
        # A worker killed after the rows committed: the redelivery finishes the Chroma steps.
        old = [_case() for _ in range(3)]
        self._seed(old)
        case = _case()
        campaign = Campaign.objects.create(title="x")
        for c in old + [case]:
            CampaignMember.objects.create(campaign=campaign, case=c)
        with patch.object(self.coll, "query", wraps=self.coll.query) as query:
            self.assertEqual(self._detect(case), campaign)
        query.assert_not_called()
        self.assertEqual(Campaign.objects.count(), 1)
        self.assertEqual(campaign.members.count(), 4)
        for c in old + [case]:
            self.assertEqual(json.loads(self.coll.docs[f"case-{c.id}"]["sourceRefs"]), [campaign.ref])

    def test_a_case_placed_while_waiting_for_the_lock_is_not_detected_again(self):
        self._seed([_case() for _ in range(3)])
        case = _case()
        assessment = _assessment(case)
        real_lock, first = campaigns.cache_lock, []

        @contextmanager
        def sibling_finishes_first(key, **kw):
            if not first:  # the other task for this case gets the lock first and places it
                first.append(None)
                first[0] = campaigns.detect_campaign(case, assessment, TEXT, HEADERS, self.profile, self.coll)
            with real_lock(key, **kw):
                yield

        with patch(f"{C}.cache_lock", sibling_finishes_first), \
                patch.object(self.coll, "query", wraps=self.coll.query) as query:
            second = campaigns.detect_campaign(case, assessment, TEXT, HEADERS, self.profile, self.coll)
        self.assertEqual(query.call_count, 1)
        self.assertEqual(second, first[0])
        self.assertEqual(Campaign.objects.count(), 1)
        self.assertEqual(second.members.count(), 4)

    def test_an_assessment_without_an_embedding_is_not_stored(self):
        self._seed([_case() for _ in range(3)])
        case = _case()
        self.assertIsNone(self._detect(case, result="INCONCLUSIVE", embedding=""))
        self.assertNotIn(f"case-{case.id}", self.coll.docs)

    def test_allow_listed_sender_domain_is_skipped(self):
        self._seed([_case() for _ in range(3)])
        case = _case()
        headers = header_dict("From: HR <hr@trusted.example>\nSubject: Verify payroll\n")
        with patch(f"{C}.is_domain_in_campaign_allow_list", side_effect=lambda d: d == "trusted.example"):
            self.assertIsNone(self._detect(case, headers=headers))
        self.assertNotIn(f"case-{case.id}", self.coll.docs)
        self.assertEqual(Campaign.objects.count(), 0)

    def test_documents_carry_the_embedding_version(self):
        lone = _case()
        self.assertIsNone(self._detect(lone))  # no neighbours: stored, no campaign
        self._seed([_case(), _case()])
        member = _case()
        self.assertIsNotNone(self._detect(member))
        for case in (lone, member):
            self.assertEqual(self.coll.docs[f"case-{case.id}"]["embedding_version"], "cmp-e1")

    def test_a_mime_encoded_subject_titles_the_campaign(self):
        subject = "Vérifiez votre paie"
        encoded = base64.b64encode(subject.encode()).decode()
        headers = header_dict(f"From: a@evil.example\nSubject: =?utf-8?B?{encoded}?=\n")
        siblings = [_case() for _ in range(4)]
        for case in siblings[:3]:
            self.assertIsNone(self._detect(case, headers=headers))
        campaign = self._detect(siblings[3], headers=headers)
        self.assertEqual(campaign.title, subject)

    def test_a_chroma_error_before_the_rows_is_raised_as_store_unavailable(self):
        failures = (
            ("query", "DANGEROUS", 3),  # the neighbour search
            ("add", "DANGEROUS", 0),  # storing a mail that is in no campaign
            ("add", "SAFE", 0),  # storing a mail of another class
        )
        for method, result, seeded in failures:
            with self.subTest(method=method, result=result):
                self.coll = FakeCollection()
                self._seed([_case() for _ in range(seeded)])
                case = _case()
                original = RuntimeError(f"chroma down: {TEXT}")
                with patch.object(self.coll, method, side_effect=original), \
                        self.assertRaises(CampaignStoreUnavailable) as raised:
                    self._detect(case, result=result)
                self.assertIs(raised.exception.__cause__, original)
                self.assertNotIn(TEXT, str(raised.exception))
                self.assertNotIn("Verify payroll", str(raised.exception))
                self.assertFalse(CampaignMember.objects.filter(case=case).exists())
        self.assertEqual(Campaign.objects.count(), 0)

    def test_a_chroma_error_after_the_rows_still_returns_the_campaign(self):
        old = [_case() for _ in range(3)]
        self._seed(old)
        case = _case()
        with patch.object(self.coll, "add", side_effect=RuntimeError(f"chroma down: {TEXT}")), \
                self.assertLogs("connectors.contrib.ai_model", "ERROR") as logs:
            campaign = self._detect(case)
        self.assertIsNotNone(campaign)
        self.assertEqual(campaign.members.count(), 4)
        self.assertNotIn(TEXT, "\n".join(logs.output))
        for c in old:  # tagged although the case's own document was not stored
            self.assertEqual(json.loads(self.coll.docs[f"case-{c.id}"]["sourceRefs"]), [campaign.ref])

    def test_a_failed_tagging_still_stores_the_case_document(self):
        self._seed([_case() for _ in range(3)])
        case = _case()
        with patch.object(self.coll, "update", side_effect=RuntimeError("chroma down")), \
                self.assertLogs("connectors.contrib.ai_model", "ERROR"):
            campaign = self._detect(case)
        self.assertEqual(campaign.members.count(), 4)
        self.assertEqual(json.loads(self.coll.docs[f"case-{case.id}"]["sourceRefs"]), [campaign.ref])

    def test_nothing_queries_the_database_after_the_rows_commit(self):
        # A failing query there would lose a campaign the caller has to announce.
        self._seed([_case() for _ in range(3)])
        case = _case()
        assessment = _assessment(case)

        def refuse(execute, sql, params, many, context):
            raise AssertionError(f"query after the rows committed: {sql}")

        @contextmanager
        def atomic_then_refuse():
            with transaction.atomic():
                yield
            blocked.enter_context(connection.execute_wrapper(refuse))

        with ExitStack() as blocked, patch(f"{C}.transaction", SimpleNamespace(atomic=atomic_then_refuse)):
            campaign = campaigns.detect_campaign(case, assessment, TEXT, HEADERS, self.profile, self.coll)
        self.assertEqual(campaign.members.count(), 4)

    def test_a_failed_lock_release_still_returns_the_campaign(self):
        self._seed([_case() for _ in range(3)])
        lock = MagicMock()
        lock.__exit__.side_effect = ConnectionError("cache down")
        with patch(f"{C}.cache_lock", return_value=lock), \
                self.assertLogs("connectors.contrib.ai_model", "ERROR"):
            self.assertIsNotNone(self._detect(_case()))

    def test_a_busy_lock_is_raised_as_store_unavailable(self):
        self._seed([_case() for _ in range(3)])
        case = _case()
        timeout = RuntimeError("Timed out waiting for lock 'campaign:detect'")
        lock = MagicMock()
        lock.__enter__.side_effect = timeout
        with patch(f"{C}.cache_lock", return_value=lock), \
                self.assertRaises(CampaignStoreUnavailable) as raised:
            self._detect(case)
        self.assertEqual(str(raised.exception), "campaign lock timed out")
        self.assertIs(raised.exception.__cause__, timeout)
        self.assertNotIn(f"case-{case.id}", self.coll.docs)
        self.assertEqual(Campaign.objects.count(), 0)

    def test_a_rerun_does_not_count_the_case_s_own_document(self):
        self._seed([_case(), _case()])
        case = _case()
        assessment = _assessment(case)

        def rerun():
            return campaigns.detect_campaign(case, assessment, TEXT, HEADERS, self.profile, self.coll)

        self.assertIsNone(rerun())  # two others: stored, no campaign
        self.assertIn(f"case-{case.id}", self.coll.docs)
        self.assertIsNone(rerun())  # its own stored document is not a third
        self._seed([_case()])
        self.assertEqual(rerun().members.count(), 4)

    def test_an_embedding_that_is_not_a_list_of_numbers_is_not_stored(self):
        self._seed([_case() for _ in range(3)])
        for embedding in ("{not json", '["a", "b"]', '{"x": 1}', "[]"):
            with self.subTest(embedding=embedding):
                case = _case()
                with self.assertLogs("connectors.contrib.ai_model", "WARNING") as logs:
                    self.assertIsNone(self._detect(case, embedding=embedding))
                self.assertNotIn(f"case-{case.id}", self.coll.docs)
                output = "\n".join(logs.output)
                self.assertIn(f"Case {case.id}", output)
                self.assertNotIn(embedding, output)
        self.assertEqual(Campaign.objects.count(), 0)


class OpenCollectionTest(TestCase):
    def test_open_collection_wraps_a_client_failure(self):
        original = RuntimeError("ChromaDB token missing")
        with patch(f"{C}.get_chroma_client", side_effect=original), \
                self.assertRaises(CampaignStoreUnavailable) as raised:
            campaigns.open_collection(current_profile())
        self.assertIs(raised.exception.__cause__, original)

    def test_open_collection_uses_the_profile_collection(self):
        client = MagicMock()
        with patch(f"{C}.get_chroma_client", return_value=client):
            collection = campaigns.open_collection(current_profile())
        self.assertEqual(client.get_or_create_collection.call_args.kwargs["name"], "suspicious_mails")
        self.assertIs(collection, client.get_or_create_collection.return_value)


class CollectionMismatchTest(TestCase):
    def mismatch(self, enabled=True, config=None, **kw):
        ConnectorState.objects.update_or_create(name="chromadb", defaults={"enabled": enabled})
        with patch("settings.config.get_section", return_value=config or {}, **kw):
            return campaigns.collection_mismatch(current_profile())

    def test_the_cleanup_default_collection_is_not_the_profile_one(self):
        message = self.mismatch()
        self.assertIn("'suspicious'", message)
        self.assertIn("'suspicious_mails'", message)
        self.assertIn("collection_name", message)
        self.assertIn("chromadb", message)

    def test_a_cleanup_connector_on_the_profile_collection_has_no_message(self):
        self.assertIsNone(self.mismatch(config={"collection_name": "suspicious_mails"}))

    def test_another_collection_name_is_named_in_the_message(self):
        self.assertIn("'old_mails'", self.mismatch(config={"collection_name": "old_mails"}))

    def test_a_disabled_cleanup_connector_has_no_message(self):
        self.assertIsNone(self.mismatch(enabled=False))

    def test_an_unreadable_cleanup_config_has_no_message_and_does_not_raise(self):
        self.assertIsNone(self.mismatch(side_effect=RuntimeError("vault down")))
