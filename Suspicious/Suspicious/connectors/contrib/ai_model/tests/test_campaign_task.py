"""Campaign detection from the ai_model connector: the case_finalised hook only queues
run_campaign_detection, which detects outside the connector's circuit breaker."""
from unittest import mock

import pybreaker
from celery.exceptions import Retry
from django.core.cache import cache
from django.test import TestCase

from case_handler.models import Campaign, CampaignMember
from common.http_client import BREAKERS, get_breaker
from connectors import tasks
from connectors.base import (
    EVENT_CAMPAIGN_UPDATED,
    EVENT_CASE_FINALISED,
    Connector,
    ConnectorManifest,
    HealthStatus,
)
from connectors.contrib.ai_model import campaigns
from connectors.contrib.ai_model.connector import AiModelConnector
from connectors.contrib.ai_model.mailtext import MailMaterial
from connectors.contrib.ai_model.tests.test_campaigns import HEADERS, TEXT, FakeCollection, _assessment, _case
from connectors.delivery import deliver_now
from connectors.dispatch import emit
from connectors.events import build_case_event
from connectors.models import ConnectorState
from connectors.providers import ProviderUnavailable
from connectors.registry import ConnectorRegistry
from connectors.tasks import run_campaign_detection
from connectors.tests.test_provider_dispatch import make_mail_case

C = "connectors.contrib.ai_model.campaigns"
CHROMA = f"{C}.get_chroma_client"
READ = "connectors.contrib.ai_model.mailtext.read_archive_material"
MATERIAL = MailMaterial("From: a@evil.example\nSubject: Verify payroll\n", TEXT)


class FakeTheHive(Connector):
    manifest = ConnectorManifest(
        name="thehive", version="0", description="Records campaign_updated.",
        events=(EVENT_CAMPAIGN_UPDATED,),
    )
    calls: list = []

    def health_check(self) -> HealthStatus:
        return HealthStatus(ok=True, detail="")

    def on_campaign_updated(self, event) -> None:
        type(self).calls.append(event)


class CampaignTaskTest(TestCase):
    def setUp(self):
        cache.delete("campaign:detect")
        registry = ConnectorRegistry()
        registry.register(AiModelConnector)
        registry.register(FakeTheHive)
        FakeTheHive.calls = []
        breaker = pybreaker.CircuitBreaker(fail_max=1, reset_timeout=60)
        self.coll = FakeCollection()
        chroma = mock.MagicMock()
        chroma.get_or_create_collection.return_value = self.coll
        patchers = [
            mock.patch.dict(BREAKERS, {"ai_model": breaker}),
            mock.patch("connectors.dispatch.registry", registry),
            mock.patch("connectors.delivery.registry", registry),
            mock.patch(CHROMA, return_value=chroma),
            mock.patch(READ, return_value=MATERIAL),
            mock.patch.object(tasks, "_mismatch_warned", False),
            mock.patch(f"{C}.collection_mismatch", return_value=None),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        for name in ("ai_model", "thehive"):
            ConnectorState.objects.update_or_create(name=name, defaults={"enabled": True})
        self.case, _ = make_mail_case()

    def seed(self, n=3):
        """Dangerous mails of other cases already in the collection, in no campaign."""
        for other in (_case() for _ in range(n)):
            self.coll.docs[f"case-{other.id}"] = {
                "suspicious_case_id": str(other.id), "classification": "DANGEROUS",
                "headers": str(HEADERS), "sourceRefs": '[""]',
            }

    def run_task(self, retries=0):
        with self.captureOnCommitCallbacks(execute=True):
            return run_campaign_detection.apply(args=(self.case.id,), retries=retries).get()

    def test_the_task_is_acked_late_and_retried_three_times(self):
        self.assertIs(run_campaign_detection.acks_late, True)
        self.assertIs(run_campaign_detection.reject_on_worker_lost, True)
        self.assertEqual(run_campaign_detection.max_retries, 3)

    def test_the_hook_only_enqueues(self):
        payload = build_case_event(EVENT_CASE_FINALISED, self.case).to_dict()
        with mock.patch("connectors.contrib.ai_model.connector.run_campaign_detection") as task, \
                mock.patch(CHROMA) as chroma:
            deliver_now("ai_model", EVENT_CASE_FINALISED, payload)
        self.assertEqual(task.mock_calls, [mock.call.delay(self.case.id)])
        chroma.assert_not_called()

    def test_a_dangerous_assessment_creates_the_campaign_and_emits_once(self):
        _assessment(self.case)
        self.seed()
        with mock.patch("connectors.dispatch.emit") as emitted:
            self.run_task()
        campaign = Campaign.objects.get()
        self.assertEqual(campaign.members.count(), 4)
        self.assertIn(f"case-{self.case.id}", self.coll.docs)
        emitted.assert_called_once()
        self.assertEqual(emitted.call_args.args[0], EVENT_CAMPAIGN_UPDATED)
        self.assertEqual(emitted.call_args.args[1].id, self.case.id)
        self.assertEqual(emitted.call_args.kwargs, {"campaign_id": campaign.id})

    def test_a_second_delivery_emits_again_and_adds_no_document_or_row(self):
        _assessment(self.case)
        self.seed()
        self.run_task()
        docs, members = dict(self.coll.docs), CampaignMember.objects.count()
        self.run_task()
        self.assertEqual(self.coll.docs, docs)
        self.assertEqual(CampaignMember.objects.count(), members)
        campaign = Campaign.objects.get()
        self.assertEqual([(e.case_id, e.campaign_id) for e in FakeTheHive.calls],
                         [(self.case.id, campaign.id)] * 2)

    def test_a_redelivery_after_a_kill_past_the_rows_stores_tags_and_emits(self):
        # The rows committed, then the worker died before the Chroma steps and the event.
        _assessment(self.case)
        self.seed()
        campaign = Campaign.objects.create(title="Verify payroll")
        member_ids = [int(meta["suspicious_case_id"]) for meta in self.coll.docs.values()]
        for cid in member_ids + [self.case.id]:
            CampaignMember.objects.create(campaign=campaign, case_id=cid)
        self.run_task()
        self.assertIn(f"case-{self.case.id}", self.coll.docs)
        for meta in self.coll.docs.values():
            self.assertEqual(meta["sourceRefs"], f'["{campaign.ref}"]')
        self.assertEqual(CampaignMember.objects.count(), 4)
        self.assertEqual([(e.case_id, e.campaign_id) for e in FakeTheHive.calls],
                         [(self.case.id, campaign.id)])

    def test_a_chroma_outage_retries_and_leaves_the_breaker_closed(self):
        _assessment(self.case)
        self.seed()
        breaker = get_breaker("ai_model")
        outage = ConnectionError(f"chroma down: {TEXT}")
        failures = (
            ("opening the collection", mock.patch(CHROMA, side_effect=outage)),
            ("the neighbour query", mock.patch.object(self.coll, "query", side_effect=outage)),
        )
        for where, failure in failures:
            with self.subTest(where=where), failure, \
                    mock.patch.object(run_campaign_detection, "retry", wraps=run_campaign_detection.retry) as retry, \
                    self.assertLogs("connectors.tasks", "WARNING") as logs:
                for retries in (0, 2):  # eager mode propagates Retry: redeliver by hand
                    with self.assertRaises(Retry) as raised:
                        self.run_task(retries)
                    self.assertNotIn(TEXT, str(raised.exception))
                    self.assertIsNone(raised.exception.__context__)
                self.assertEqual([c.kwargs["countdown"] for c in retry.call_args_list], [30, 120])
                self.assertEqual((breaker.fail_counter, breaker.current_state), (0, "closed"))
                self.assertIn(f"case {self.case.id}", logs.output[0])
                self.assertIn("CampaignStoreUnavailable", logs.output[0])
                self.assertNotIn(TEXT, "\n".join(logs.output))
                self.assertFalse(CampaignMember.objects.exists())
                self.assertEqual(FakeTheHive.calls, [])

    def test_a_placed_case_is_announced_and_retried_when_the_collection_cannot_be_opened(self):
        _assessment(self.case)
        campaign = Campaign.objects.create(title="Verify payroll")
        CampaignMember.objects.create(campaign=campaign, case=self.case)
        with mock.patch(CHROMA, side_effect=ConnectionError(f"chroma down: {TEXT}")), \
                mock.patch.object(run_campaign_detection, "retry", wraps=run_campaign_detection.retry) as retry, \
                self.assertLogs("connectors.tasks", "WARNING") as logs:
            with self.assertRaises(Retry):
                self.run_task()
        self.assertEqual([c.kwargs["countdown"] for c in retry.call_args_list], [30])
        self.assertEqual([(e.case_id, e.campaign_id) for e in FakeTheHive.calls],
                         [(self.case.id, campaign.id)])
        self.assertEqual(self.coll.docs, {})
        self.assertIn(f"Case {self.case.id}", logs.output[0])
        self.assertIn("CampaignStoreUnavailable", logs.output[0])
        self.assertNotIn(TEXT, "\n".join(logs.output))

    def test_the_last_retry_of_a_placed_case_announces_and_ends(self):
        _assessment(self.case)
        campaign = Campaign.objects.create(title="Verify payroll")
        CampaignMember.objects.create(campaign=campaign, case=self.case)
        with mock.patch(CHROMA, side_effect=ConnectionError("chroma down")), \
                mock.patch.object(run_campaign_detection, "retry") as retry:
            self.assertIsNone(self.run_task(retries=3))
        retry.assert_not_called()
        self.assertEqual([(e.case_id, e.campaign_id) for e in FakeTheHive.calls],
                         [(self.case.id, campaign.id)])

    def test_exhausted_retries_log_and_return(self):
        _assessment(self.case)
        self.seed()
        with mock.patch(f"{C}.detect_campaign", side_effect=ValueError(f"bad header: {TEXT}")), \
                mock.patch.object(run_campaign_detection, "retry") as retry, \
                self.assertLogs("connectors.tasks", "ERROR") as logs:
            self.assertIsNone(self.run_task(retries=3))
        retry.assert_not_called()
        self.assertIn(f"case {self.case.id}", logs.output[0])
        self.assertIn("ValueError", logs.output[0])
        self.assertNotIn(TEXT, "\n".join(logs.output))
        self.assertFalse(CampaignMember.objects.exists())

    def test_a_retryable_material_read_failure_retries(self):
        _assessment(self.case)
        with mock.patch(READ,
                        side_effect=ProviderUnavailable("object store unavailable: unavailable")), \
                mock.patch.object(run_campaign_detection, "retry", wraps=run_campaign_detection.retry) as retry, \
                self.assertRaises(Retry):
            self.run_task()
        self.assertEqual(retry.call_args.kwargs["countdown"], 30)

    def test_a_non_retryable_material_read_failure_logs_and_returns(self):
        _assessment(self.case)
        with mock.patch(READ,
                        side_effect=ProviderUnavailable("object store unavailable: access_denied",
                                                        retryable=False)), \
                mock.patch.object(run_campaign_detection, "retry") as retry, \
                self.assertLogs("connectors.tasks", "ERROR") as logs:
            self.assertIsNone(self.run_task())
        retry.assert_not_called()
        self.assertIn(f"case {self.case.id}", logs.output[0])
        self.assertIn("ProviderUnavailable", logs.output[0])

    def test_a_deleted_case_returns_quietly(self):
        with mock.patch.object(run_campaign_detection, "retry") as retry, \
                self.assertLogs("connectors.tasks", "INFO") as logs:
            self.assertIsNone(run_campaign_detection.apply(args=(987654,)).get())
        retry.assert_not_called()
        self.assertEqual([r.levelname for r in logs.records], ["INFO"])
        self.assertIn("987654", logs.output[0])

    def test_malformed_headers_still_detect_with_no_headers(self):
        _assessment(self.case)
        self.seed()
        with mock.patch("connectors.contrib.ai_model.mailtext.header_dict",
                        side_effect=ValueError(f"bad header: {TEXT}")), \
                mock.patch(f"{C}.detect_campaign", wraps=campaigns.detect_campaign) as detect, \
                self.assertLogs("connectors.tasks", "WARNING") as logs:
            self.run_task()
        self.assertEqual(detect.call_args.args[3], {})
        self.assertEqual(Campaign.objects.get().members.count(), 4)
        self.assertIn(f"Case {self.case.id}", logs.output[0])
        self.assertIn("ValueError", logs.output[0])
        self.assertNotIn(TEXT, "\n".join(logs.output))

    def test_no_assessment_means_no_work(self):
        with mock.patch(CHROMA) as chroma, \
                mock.patch(READ) as read, \
                self.assertLogs("connectors.tasks", "INFO") as logs:
            self.assertIsNone(self.run_task())
        chroma.assert_not_called()
        read.assert_not_called()
        self.assertIn(f"Case {self.case.id}", logs.output[0])
        self.assertEqual(FakeTheHive.calls, [])

    def test_no_mail_text_means_no_work(self):
        _assessment(self.case)
        with mock.patch(CHROMA) as chroma, \
                mock.patch(READ, return_value=None):
            self.assertIsNone(self.run_task())
        chroma.assert_not_called()
        self.assertEqual(self.coll.docs, {})

    def test_a_disabled_connector_receives_no_case_finalised(self):
        ConnectorState.objects.filter(name="ai_model").update(enabled=False)
        with mock.patch("connectors.contrib.ai_model.connector.run_campaign_detection") as task, \
                self.captureOnCommitCallbacks(execute=True):
            emit(EVENT_CASE_FINALISED, self.case)
        task.delay.assert_not_called()
        ConnectorState.objects.filter(name="ai_model").update(enabled=True)
        with mock.patch("connectors.contrib.ai_model.connector.run_campaign_detection") as task, \
                self.captureOnCommitCallbacks(execute=True):
            emit(EVENT_CASE_FINALISED, self.case)
        task.delay.assert_called_once_with(self.case.id)

    def test_the_thehive_connector_receives_campaign_updated(self):
        _assessment(self.case)
        self.seed()
        self.run_task()
        campaign = Campaign.objects.get()
        [event] = FakeTheHive.calls
        self.assertEqual((event.event, event.case_id, event.campaign_id),
                         (EVENT_CAMPAIGN_UPDATED, self.case.id, campaign.id))

    def test_the_collection_warning_is_logged_once_across_two_runs(self):
        _assessment(self.case)
        sentence = "The chromadb cleanup watches 'suspicious', not 'suspicious_mails'."
        with mock.patch(f"{C}.collection_mismatch", return_value=sentence), \
                self.assertLogs("connectors.tasks", "WARNING") as logs:
            self.run_task()
            self.run_task()
        self.assertEqual(logs.output, [f"WARNING:connectors.tasks:{sentence}"])

    def test_no_mismatch_logs_nothing_and_is_checked_again_next_run(self):
        _assessment(self.case)
        with mock.patch(f"{C}.collection_mismatch", return_value=None) as check, \
                self.assertNoLogs("connectors.tasks", "WARNING"):
            self.run_task()
            self.run_task()
        self.assertEqual(check.call_count, 2)

    def test_an_unimportable_collection_check_neither_fails_nor_retries_the_task(self):
        with mock.patch.dict("sys.modules", {"connectors.contrib.ai_model.campaigns": None}), \
                self.assertLogs("connectors.tasks", "DEBUG") as logs:
            tasks._warn_collection_mismatch(mock.Mock(collection_name="suspicious_mails"))
        self.assertIn("ModuleNotFoundError", logs.output[0])

    def test_a_failing_collection_check_neither_fails_nor_retries_the_task(self):
        _assessment(self.case)
        with mock.patch(f"{C}.collection_mismatch", side_effect=RuntimeError(f"vault: {TEXT}")), \
                mock.patch.object(run_campaign_detection, "retry") as retry, \
                self.assertNoLogs("connectors.tasks", "WARNING"):
            self.assertIsNone(self.run_task())
        retry.assert_not_called()
        self.assertIn(f"case-{self.case.id}", self.coll.docs)
