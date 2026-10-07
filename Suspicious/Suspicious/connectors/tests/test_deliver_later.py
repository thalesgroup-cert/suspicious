"""A hook can say "not ready yet": no ledger row, no breaker failure, a quick retry."""
from unittest import mock

from celery.exceptions import Retry
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from common.http_client import get_breaker
from connectors.delivery import MAX_ATTEMPTS, MAX_DEFERRALS, DeliverLater, RetryableDeliveryError, deliver_now
from connectors.models import ConnectorDelivery
from connectors.tasks import deliver_event
from connectors.tests.dummy import DummyConnector


class LaterConnector(DummyConnector):
    def on_case_finalised(self, event) -> None:
        raise DeliverLater("MailInfo not written yet", countdown=7)


def _payload():
    user = get_user_model().objects.create_user(username="rep", email="r@e.c", password="x")
    case = Case.objects.create(reporter=user, description="t")
    return {"schema_version": 1, "event": "case_finalised", "case_id": case.id, "status": "Done",
            "results": "Safe", "final_score": None, "confidence": None, "reporter_email": "",
            "created_at": "", "campaign_id": None}


class DeliverNowTest(TestCase):
    def setUp(self):
        from connectors.registry import ConnectorRegistry
        registry = ConnectorRegistry()
        registry.register(LaterConnector)
        for target in ("connectors.dispatch.registry", "connectors.delivery.registry"):
            p = mock.patch(target, registry)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch("connectors.registry.ConnectorRegistry.instantiate",
                       lambda reg, name: reg.get(name)({"url": "http://x"}))
        p.start()
        self.addCleanup(p.stop)
        get_breaker("dummy").close()

    def test_a_deferral_leaves_no_ledger_row(self):
        with self.assertRaises(DeliverLater) as ctx:
            deliver_now("dummy", "case_finalised", _payload())
        self.assertEqual(ctx.exception.countdown, 7)
        self.assertEqual(ConnectorDelivery.objects.count(), 0)

    def test_deferrals_never_trip_the_circuit_breaker(self):
        payload = _payload()
        for _ in range(20):
            with self.assertRaises(DeliverLater):
                deliver_now("dummy", "case_finalised", payload)
        breaker = get_breaker("dummy")
        self.assertEqual(breaker.fail_counter, 0)
        self.assertEqual(breaker.current_state, "closed")

    def test_still_not_ready_after_the_cap_becomes_a_real_failure(self):
        payload = _payload()
        with self.assertRaises(RetryableDeliveryError):
            deliver_now("dummy", "case_finalised", payload, attempt=1, deferrals=MAX_DEFERRALS)
        row = ConnectorDelivery.objects.get()
        self.assertEqual(row.status, ConnectorDelivery.STATUS_FAILED)
        self.assertIn("MailInfo not written yet", row.error)
        self.assertIn("deferr", row.error)

    def test_the_last_real_attempt_after_the_cap_does_not_retry_again(self):
        deliver_now("dummy", "case_finalised", _payload(), attempt=MAX_ATTEMPTS, deferrals=MAX_DEFERRALS)
        self.assertEqual(ConnectorDelivery.objects.get().status, ConnectorDelivery.STATUS_FAILED)


class TaskTest(TestCase):
    def _run(self, *, deferrals, retries, deliver_side_effect=None):
        payload = _payload()
        with mock.patch("connectors.delivery.deliver_now", side_effect=deliver_side_effect) as deliver, \
                mock.patch.object(deliver_event, "retry", side_effect=Retry()) as retry:
            try:
                deliver_event.apply(args=("dummy", "case_finalised", payload),
                                    kwargs={"deferrals": deferrals}, retries=retries)
            except Retry:
                pass
        return deliver, retry

    def test_a_deferral_reschedules_quickly_and_counts_separately_from_attempts(self):
        _deliver, retry = self._run(deferrals=3, retries=3, deliver_side_effect=DeliverLater("later", countdown=7))
        kwargs = retry.call_args.kwargs
        self.assertEqual(kwargs["countdown"], 7)
        self.assertEqual(kwargs["kwargs"], {"deferrals": 4})
        self.assertGreaterEqual(kwargs["max_retries"], MAX_DEFERRALS + MAX_ATTEMPTS)

    def test_real_attempts_ignore_earlier_deferrals(self):
        deliver, _retry = self._run(deferrals=5, retries=5)
        self.assertEqual(deliver.call_args.kwargs["attempt"], 1)
        self.assertEqual(deliver.call_args.kwargs["deferrals"], 5)

    def test_a_real_failure_still_backs_off_by_attempt_not_by_deferrals(self):
        _deliver, retry = self._run(deferrals=6, retries=6, deliver_side_effect=RetryableDeliveryError("boom"))
        self.assertEqual(retry.call_args.kwargs["countdown"], 30)  # first real attempt
        self.assertEqual(retry.call_args.kwargs["kwargs"], {"deferrals": 6})

    def test_the_second_real_attempt_waits_longer(self):
        _deliver, retry = self._run(deferrals=6, retries=7, deliver_side_effect=RetryableDeliveryError("boom"))
        self.assertEqual(retry.call_args.kwargs["countdown"], 60)
