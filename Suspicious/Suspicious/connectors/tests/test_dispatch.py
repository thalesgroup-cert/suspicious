from unittest import mock

import pybreaker
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from connectors.base import EVENT_CASE_FINALISED
from connectors.models import ConnectorDelivery, ConnectorState
from connectors.tests.dummy import DummyConnector


def make_case():
    user = get_user_model().objects.create_user(
        username="rep", email="rep@example.com", password="x"
    )
    return Case.objects.create(
        reporter=user, status="Done", results="Safe", description="t"
    )


def make_payload(case):
    return {
        "schema_version": 1, "event": EVENT_CASE_FINALISED,
        "case_id": case.id, "status": "Done", "results": "Safe",
        "final_score": None, "confidence": None,
        "reporter_email": "", "created_at": "",
    }


class DispatchTest(TestCase):
    def setUp(self):
        DummyConnector.calls = []
        from connectors.registry import ConnectorRegistry
        self.registry = ConnectorRegistry()
        self.registry.register(DummyConnector)
        for target in ("connectors.dispatch.registry", "connectors.delivery.registry"):
            patcher = mock.patch(target, self.registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher_c = mock.patch(
            "connectors.registry.ConnectorRegistry.instantiate",
            lambda reg, name: reg.get(name)({"url": "http://x"}),
        )
        patcher_c.start()
        self.addCleanup(patcher_c.stop)

    def test_emit_delivers_to_enabled_subscriber(self):
        ConnectorState.objects.create(name="dummy", enabled=True)
        case = make_case()
        from connectors.dispatch import emit
        with self.captureOnCommitCallbacks(execute=True):
            emit(EVENT_CASE_FINALISED, case)
        self.assertEqual(len(DummyConnector.calls), 1)
        row = ConnectorDelivery.objects.get()
        self.assertEqual(
            (row.connector, row.event, row.status),
            ("dummy", EVENT_CASE_FINALISED, ConnectorDelivery.STATUS_SUCCESS),
        )

    def test_emit_skips_disabled_connector(self):
        ConnectorState.objects.create(name="dummy", enabled=False)
        case = make_case()
        from connectors.dispatch import emit
        with self.captureOnCommitCallbacks(execute=True):
            emit(EVENT_CASE_FINALISED, case)
        self.assertEqual(DummyConnector.calls, [])
        self.assertEqual(ConnectorDelivery.objects.count(), 0)

    def test_emit_creates_state_with_manifest_default(self):
        case = make_case()
        from connectors.dispatch import emit
        with self.captureOnCommitCallbacks(execute=True):
            emit(EVENT_CASE_FINALISED, case)
        state = ConnectorState.objects.get(name="dummy")
        self.assertFalse(state.enabled)

    def test_hook_failure_writes_failed_row_and_never_raises(self):
        ConnectorState.objects.create(name="dummy", enabled=True)
        case = make_case()
        from connectors import delivery as delivery_mod
        with mock.patch.object(
            DummyConnector, "on_case_finalised", side_effect=RuntimeError("boom")
        ):
            delivery_mod.deliver_now(
                "dummy", EVENT_CASE_FINALISED, make_payload(case),
                attempt=delivery_mod.MAX_ATTEMPTS,
            )
        row = ConnectorDelivery.objects.get()
        self.assertEqual(row.status, ConnectorDelivery.STATUS_FAILED)
        self.assertIn("boom", row.error)

    def test_hook_failure_below_max_attempts_raises_retryable(self):
        ConnectorState.objects.create(name="dummy", enabled=True)
        case = make_case()
        from connectors import delivery as delivery_mod
        with mock.patch.object(
            DummyConnector, "on_case_finalised", side_effect=RuntimeError("boom")
        ):
            with self.assertRaises(delivery_mod.RetryableDeliveryError):
                delivery_mod.deliver_now(
                    "dummy", EVENT_CASE_FINALISED, make_payload(case), attempt=1,
                )
        row = ConnectorDelivery.objects.get()
        self.assertEqual(row.status, ConnectorDelivery.STATUS_FAILED)
        self.assertEqual(row.attempt, 1)

    def test_open_breaker_writes_skipped_row(self):
        ConnectorState.objects.create(name="dummy", enabled=True)
        case = make_case()
        from common.http_client import BREAKERS
        from connectors import delivery as delivery_mod

        prev_breaker = BREAKERS.get("dummy")
        BREAKERS["dummy"] = pybreaker.CircuitBreaker(fail_max=1, reset_timeout=600)
        def _restore():
            if prev_breaker is None:
                BREAKERS.pop("dummy", None)
            else:
                BREAKERS["dummy"] = prev_breaker
        self.addCleanup(_restore)

        try:
            BREAKERS["dummy"].call(lambda: (_ for _ in ()).throw(RuntimeError("x")))
        except Exception:
            pass
        delivery_mod.deliver_now(
            "dummy", EVENT_CASE_FINALISED, make_payload(case), attempt=1,
        )
        row = ConnectorDelivery.objects.get()
        self.assertEqual(row.status, ConnectorDelivery.STATUS_SKIPPED)

    def test_run_sync_now_records_success(self):
        ConnectorState.objects.create(name="dummy", enabled=True)
        from connectors.delivery import run_sync_now
        run_sync_now("dummy")
        self.assertIn("sync", DummyConnector.calls)
        row = ConnectorDelivery.objects.get()
        self.assertEqual((row.event, row.status), ("sync", "success"))

    def test_run_sync_now_skips_disabled(self):
        ConnectorState.objects.create(name="dummy", enabled=False)
        from connectors.delivery import run_sync_now
        run_sync_now("dummy")
        self.assertEqual(DummyConnector.calls, [])
