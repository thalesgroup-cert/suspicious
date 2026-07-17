"""Unit tests for the FeederHealthView staleness / status derivation.

The view proxies the email_feeder /health endpoint. Older feeder builds do
not report a `status` field, so the proxy must derive ok|degraded from its
own staleness view — otherwise the badge shows "ok" while `stale` is True.
"""
import time
from unittest import mock

from django.test import SimpleTestCase

from api.views.feeder_health import FeederHealthView, _FEEDER_STALE_THRESHOLD_S


class _FakeResp:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _call(feeder_payload):
    with mock.patch(
        "api.views.feeder_health.requests.get",
        return_value=_FakeResp(feeder_payload),
    ):
        return FeederHealthView().get(None).data


class FeederHealthStatusDerivationTest(SimpleTestCase):
    def test_missing_status_with_stale_poll_derives_degraded(self):
        old = int(time.time()) - (_FEEDER_STALE_THRESHOLD_S + 60)
        data = _call({"last_successful_poll": old})
        self.assertEqual(data["feeder_status"], "degraded")
        self.assertTrue(data["stale"])

    def test_missing_status_with_fresh_poll_derives_ok(self):
        fresh = int(time.time()) - 5
        data = _call({"last_successful_poll": fresh})
        self.assertEqual(data["feeder_status"], "ok")
        self.assertFalse(data["stale"])

    def test_missing_status_never_polled_derives_degraded(self):
        data = _call({"last_successful_poll": 0})
        self.assertEqual(data["feeder_status"], "degraded")
        self.assertTrue(data["stale"])
        self.assertIsNone(data["last_successful_poll"])

    def test_explicit_degraded_is_passed_through(self):
        fresh = int(time.time()) - 5
        data = _call({"status": "degraded", "last_successful_poll": fresh})
        self.assertEqual(data["feeder_status"], "degraded")
        self.assertTrue(data["stale"])

    def test_explicit_ok_but_stale_poll_keeps_status_marks_stale(self):
        old = int(time.time()) - (_FEEDER_STALE_THRESHOLD_S + 60)
        data = _call({"status": "ok", "last_successful_poll": old})
        self.assertEqual(data["feeder_status"], "ok")
        self.assertTrue(data["stale"])
