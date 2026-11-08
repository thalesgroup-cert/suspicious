"""Ruling F7: the shadow model's campaign dry run reads the live collection and writes one
ShadowCampaignEffect row, nothing else."""
from unittest import mock

from celery.exceptions import Retry
from django.test import TestCase

from ai_model import registry
from ai_model.campaign_profile import current_profile
from ai_model.models import ShadowCampaignEffect, ShadowResult
from ai_model.tests.test_registry import cand
from case_handler.models import Campaign, CampaignMember
from connectors.base import EVENT_CASE_FINALISED
from connectors.contrib.ai_model import dryrun
from connectors.contrib.ai_model.connector import AiModelConnector
from connectors.contrib.ai_model.mailtext import MailMaterial
from connectors.contrib.ai_model.tests.test_campaigns import HEADERS, TEXT, _assessment, _case
from connectors.models import ConnectorDelivery
from connectors.tasks import run_shadow_campaign
from connectors.tests.test_provider_dispatch import make_mail_case

E = ShadowCampaignEffect.Effect
C = "connectors.contrib.ai_model.campaigns"
READ = "connectors.contrib.ai_model.mailtext.read_archive_material"


class ReadOnlyCollection:
    """Every stored mail is a neighbour at its stored distance; writes are recorded."""

    def __init__(self):
        self.docs, self.writes, self.queries = {}, [], []

    def query(self, **kw):
        self.queries.append(kw)
        hits = list(self.docs.items())[:kw["n_results"]]
        return {"ids": [[i for i, _ in hits]], "metadatas": [[m for _, (m, _) in hits]],
                "documents": [["" for _ in hits]], "embeddings": [[[0] for _ in hits]],
                "distances": [[d for _, (_, d) in hits]]}

    def __getattr__(self, name):
        if name in ("add", "update", "upsert", "delete", "modify"):
            return lambda *a, **kw: self.writes.append(name)
        raise AttributeError(name)


class DryRunTest(TestCase):
    def setUp(self):
        self.version = registry.set_shadow(cand("s1", manifest={"eligible": True}))
        self.coll = ReadOnlyCollection()
        self.profile = current_profile()

    def shadow(self, case, result="DANGEROUS", version=None):
        return ShadowResult.objects.update_or_create(case=case, version=version or self.version, defaults={
            "result": result, "score": 9, "confidence": 90, "origin": "seed"})[0]

    def neighbour(self, result="DANGEROUS", distance=0.1, live="SAFE"):
        case = _case()
        if result:
            self.shadow(case, result)
        # The live class is irrelevant: the dry run asks without a class filter.
        self.coll.docs[f"case-{case.id}"] = ({"suspicious_case_id": str(case.id), "classification": live,
                                               "headers": str(HEADERS)}, distance)
        return case

    def dry(self, case=None, result="DANGEROUS", headers=HEADERS):
        case = case or _case()
        assessment = getattr(case, "ai_assessment", None) or _assessment(case, "SAFE")  # the live class does not matter
        return dryrun.dry_run_campaign(case, self.shadow(case, result), assessment,
                                       headers, self.profile, self.coll)

    def test_three_candidate_dangerous_neighbours_would_create(self):
        old = [self.neighbour() for _ in range(3)]
        row = self.dry()
        self.assertEqual(row.effect, E.WOULD_CREATE)
        self.assertEqual(set(row.member_case_ids), {c.id for c in old} | {row.case_id})
        self.assertIsNone(row.live_campaign)

    def test_a_neighbour_in_a_live_campaign_would_join_it(self):
        old = [self.neighbour() for _ in range(3)]
        campaign = Campaign.objects.create(title="x")
        CampaignMember.objects.create(campaign=campaign, case=old[0])
        row = self.dry()
        self.assertEqual((row.effect, row.live_campaign), (E.WOULD_JOIN, campaign))
        self.assertEqual(set(row.member_case_ids), {c.id for c in old} | {row.case_id})

    def test_a_case_the_candidate_calls_safe_is_not_checked(self):
        [self.neighbour() for _ in range(3)]
        self.assertEqual(self.dry(result="SAFE").effect, E.NO_CHECK)
        self.assertEqual(self.coll.queries, [])

    def test_too_few_neighbours_is_none(self):
        self.neighbour(), self.neighbour(), self.neighbour(distance=0.3)
        row = self.dry()
        self.assertEqual((row.effect, row.member_case_ids), (E.NONE, []))

    def test_an_allow_listed_sender_is_not_checked(self):
        [self.neighbour() for _ in range(3)]
        with mock.patch.object(dryrun, "is_domain_in_campaign_allow_list", return_value=True):
            self.assertEqual(self.dry().effect, E.NO_CHECK)

    def test_neighbours_the_candidate_does_not_call_dangerous_do_not_count(self):
        counted = [self.neighbour(), self.neighbour()]
        self.neighbour(result=None, live="DANGEROUS")  # no ShadowResult
        self.neighbour(result="SAFE", live="DANGEROUS")
        self.shadow(self.neighbour(result=None), "DANGEROUS", version=cand("s0"))  # another version
        self.assertEqual(self.dry().effect, E.NONE)
        counted.append(self.neighbour())
        row = self.dry()
        self.assertEqual(row.effect, E.WOULD_CREATE)
        self.assertEqual(set(row.member_case_ids), {c.id for c in counted} | {row.case_id})

    def test_the_query_asks_60_neighbours_without_class_filter_and_writes_nothing(self):
        [self.neighbour() for _ in range(3)]
        with mock.patch("connectors.dispatch.emit") as emitted:
            self.dry()
            self.dry()
        self.assertEqual(len(self.coll.queries), 2)
        self.assertEqual(self.coll.queries[0]["n_results"], 60)
        self.assertNotIn("where", self.coll.queries[0])
        self.assertEqual(self.coll.writes, [])
        self.assertFalse(Campaign.objects.exists())
        self.assertFalse(CampaignMember.objects.exists())
        self.assertFalse(ConnectorDelivery.objects.exists())
        emitted.assert_not_called()

    def test_the_own_document_is_not_a_neighbour(self):
        case = _case()
        self.coll.docs[f"case-{case.id}"] = ({"suspicious_case_id": str(case.id)}, 0.0)
        self.neighbour(), self.neighbour()
        self.assertEqual(self.dry(case).effect, E.NONE)

    def test_a_redelivery_overwrites_the_same_row(self):
        case = _case()
        self.assertEqual(self.dry(case).effect, E.NONE)
        [self.neighbour() for _ in range(3)]
        self.assertEqual(self.dry(case).effect, E.WOULD_CREATE)
        self.assertEqual(ShadowCampaignEffect.objects.filter(case=case).count(), 1)

    def test_the_module_has_no_writing_helper(self):
        for name in ("add_to_suspicious_collection", "set_campaign_ref", "detect_campaign",
                     "_store_and_tag", "Campaign", "emit", "campaigns"):
            self.assertFalse(hasattr(dryrun, name), name)


class ShadowCampaignTaskTest(TestCase):
    def setUp(self):
        self.version = registry.set_shadow(cand("s1", manifest={"eligible": True}))
        self.case, _ = make_mail_case()
        _assessment(self.case, "SAFE")
        ShadowResult.objects.create(case=self.case, version=self.version, result="DANGEROUS",
                                    score=9, confidence=90)
        patcher = mock.patch(READ, return_value=MailMaterial("From: a@evil.example\n", TEXT))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_chroma_down_records_nothing_and_retries(self):
        with mock.patch(f"{C}.get_chroma_client", side_effect=ConnectionError(TEXT)), \
                mock.patch.object(run_shadow_campaign, "retry", wraps=run_shadow_campaign.retry) as retry, \
                self.assertLogs("connectors.tasks", "WARNING") as logs:
            with self.assertRaises(Retry):
                run_shadow_campaign.apply(args=(self.case.id,)).get()
        self.assertEqual([c.kwargs["countdown"] for c in retry.call_args_list], [30])
        self.assertFalse(ShadowCampaignEffect.objects.exists())
        self.assertIn("CampaignStoreUnavailable", logs.output[0])
        self.assertNotIn(TEXT, "\n".join(logs.output))

    def test_the_task_records_the_effect(self):
        coll = ReadOnlyCollection()
        chroma = mock.MagicMock()
        chroma.get_or_create_collection.return_value = coll
        with mock.patch(f"{C}.get_chroma_client", return_value=chroma):
            run_shadow_campaign.apply(args=(self.case.id,)).get()
        self.assertEqual(ShadowCampaignEffect.objects.get().effect, E.NONE)
        self.assertEqual(coll.writes, [])

    def test_no_shadow_row_records_nothing(self):
        ShadowResult.objects.all().delete()
        with mock.patch(f"{C}.get_chroma_client") as chroma:
            run_shadow_campaign.apply(args=(self.case.id,)).get()
        chroma.assert_not_called()
        self.assertFalse(ShadowCampaignEffect.objects.exists())


class HookTest(TestCase):
    def setUp(self):
        self.case, _ = make_mail_case()
        self.connector = AiModelConnector(config={})
        self.event = mock.Mock(case_id=self.case.id, name=EVENT_CASE_FINALISED)

    def hook(self):
        with mock.patch("connectors.contrib.ai_model.connector.run_campaign_detection") as live, \
                mock.patch("connectors.contrib.ai_model.connector.run_shadow_campaign") as shadow:
            self.connector.on_case_finalised(self.event)
        return live, shadow

    def test_queued_only_when_a_shadow_exists(self):
        live, shadow = self.hook()
        live.delay.assert_called_once_with(self.case.id)
        shadow.delay.assert_not_called()
        registry.set_shadow(cand("s1", manifest={"eligible": True}))
        live, shadow = self.hook()
        shadow.delay.assert_called_once_with(self.case.id)
