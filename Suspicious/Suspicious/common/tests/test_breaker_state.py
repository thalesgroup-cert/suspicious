"""Plan G, Task 5: breaker state published to the shared cache, and the epoch reset."""
from unittest import mock

import pybreaker
from django.core.cache import cache
from django.test import SimpleTestCase

from common import http_client as hc


def boom():
    raise RuntimeError("down")


def fail(b, times):
    for _ in range(times):
        try:
            b.call(boom)
        except (RuntimeError, pybreaker.CircuitBreakerError):
            pass


class BreakerStateTest(SimpleTestCase):
    def setUp(self):
        cache.clear()
        patcher = mock.patch.object(hc, "EPOCH_CHECK_SECONDS", 0)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.b = hc._new_breaker("tb")

    def test_listener_publishes_each_state_change(self):
        self.assertEqual(hc.breaker_state("tb"), {"state": "unknown", "since": None})
        fail(self.b, 5)
        got = cache.get("breaker:tb")
        self.assertEqual(got["state"], "open")
        self.assertTrue(got["since"])
        self.assertEqual(hc.breaker_state("tb"), got)
        self.b.close()
        self.assertEqual(hc.breaker_state("tb")["state"], "closed")

    def test_publish_failure_never_breaks_a_call_and_logs_once(self):
        with mock.patch.object(hc.cache, "set", side_effect=ConnectionError("redis down")), \
                self.assertLogs("common.http_client", "WARNING") as logs:
            fail(self.b, 5)  # opening publishes: must not raise anything but the breaker's own error
            self.b.close()
            self.b.open()
        self.assertEqual(self.b.current_state, "open")
        self.assertEqual(sum("could not publish" in m for m in logs.output), 1)

    def test_state_unknown_when_cache_raises_or_value_is_junk(self):
        with mock.patch.object(hc.cache, "get", side_effect=ConnectionError("redis down")):
            self.assertEqual(hc.breaker_state("tb"), {"state": "unknown", "since": None})
        cache.set("breaker:tb", "garbage")
        self.assertEqual(hc.breaker_state("tb"), {"state": "unknown", "since": None})

    def test_request_reset_increments_the_epoch(self):
        self.assertEqual(hc.request_reset("tb"), 1)
        self.assertEqual(hc.request_reset("tb"), 2)
        self.assertEqual(cache.get("breaker-epoch:tb"), 2)
        self.assertIsNone(cache.get("breaker-epoch:other"))

    def test_open_breaker_closes_before_the_next_call_after_a_reset(self):
        self.b.call(lambda: None)
        fail(self.b, 5)
        self.assertEqual(self.b.current_state, "open")
        epoch = hc.request_reset("tb")
        self.assertEqual(self.b.call(lambda: "ok"), "ok")
        self.assertEqual(self.b.current_state, "closed")
        self.assertEqual(self.b._epoch, epoch)

    def test_close_once_per_epoch_move(self):
        hc.request_reset("tb")
        self.b.call(lambda: None)  # first sight of epoch 1 on a closed breaker: recorded, no close
        with mock.patch.object(self.b, "close", wraps=self.b.close) as close:
            self.b.call(lambda: None)
            self.assertEqual(close.call_count, 0)
            hc.request_reset("tb")
            self.b.call(lambda: None)
            self.b.call(lambda: None)
            self.assertEqual(close.call_count, 1)

    def test_reset_does_not_stop_five_new_failures_reopening(self):
        fail(self.b, 5)
        hc.request_reset("tb")
        fail(self.b, 4)
        self.assertEqual(self.b.current_state, "closed")
        fail(self.b, 1)
        self.assertEqual(self.b.current_state, "open")
        self.assertEqual(hc.breaker_state("tb")["state"], "open")

    def test_epoch_check_fails_open_when_the_cache_is_down(self):
        fail(self.b, 5)
        with mock.patch.object(hc.cache, "get", side_effect=ConnectionError("redis down")):
            with self.assertRaises(pybreaker.CircuitBreakerError):
                self.b.call(lambda: None)  # still open: behaves as before
        b2 = hc._new_breaker("tb2")
        with mock.patch.object(hc.cache, "get", side_effect=ConnectionError("redis down")):
            self.assertEqual(b2.call(lambda: "ok"), "ok")

    def test_epoch_read_is_throttled(self):
        with mock.patch.object(hc, "EPOCH_CHECK_SECONDS", 60), \
                mock.patch.object(hc.cache, "get", wraps=hc.cache.get) as get:
            b = hc._new_breaker("tb3")
            for _ in range(3):
                b.call(lambda: None)
            with b.calling():
                pass
        self.assertEqual(get.call_count, 1)

    def test_calling_context_manager_checks_the_epoch_too(self):
        fail(self.b, 5)
        hc.request_reset("tb")
        with self.b.calling():
            pass
        self.assertEqual(self.b.current_state, "closed")
