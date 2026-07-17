from unittest.mock import MagicMock, patch

import requests
from django.test import TestCase

from common.http_client import RETRY, TimeoutHTTPAdapter
from cortex_job.cortex_utils.session_cortex_api import SessionCortexApi


class SessionCortexApiTest(TestCase):
    """R5 regression: cortex4py.Api was making bare requests.get/post
    calls — no Session, no socket-level timeout. SessionCortexApi must
    route every do_* through a shared requests.Session that has our
    TimeoutHTTPAdapter mounted.
    """

    def _make(self):
        return SessionCortexApi(
            "http://cortex.invalid:9001", "k", proxies={"http": "", "https": ""}
        )

    def test_session_has_timeout_adapter_mounted(self):
        api = self._make()
        for scheme in ("http://", "https://"):
            self.assertIsInstance(api._session.adapters[scheme], TimeoutHTTPAdapter)

    def test_do_get_routes_through_session(self):
        api = self._make()
        api._session = MagicMock()
        api._session.request.return_value = MagicMock(
            raise_for_status=MagicMock(return_value=None)
        )

        api.do_get("status")

        args, kwargs = api._session.request.call_args
        self.assertEqual(args[0], "GET")
        self.assertEqual(args[1], "http://cortex.invalid:9001/api/status")
        self.assertIn("Authorization", kwargs["headers"])
        self.assertTrue(kwargs["headers"]["Authorization"].startswith("Bearer "))


class SessionCortexApiRetryIntegrationTest(TestCase):
    """Regression: SessionCortexApi._execute() unconditionally calls cortex4py's
    Api.__recover() on any exception, which rewraps a requests.HTTPError into
    a cortex4py-specific exception (InvalidInputError for any non-404/401/403
    status, including 500) that is NOT a subclass of requests.HTTPError or
    requests.RequestException (confirmed directly against the installed
    cortex4py package). common.http_client.RETRY's _is_retryable_http_error
    predicate only recognizes a bare requests.HTTPError with status>=500, so
    it never matches the wrapped exception — every genuinely-retryable Cortex
    5xx across the whole integration (_fetch_job, _fetch_report, analyzer
    dispatch) gets zero retries instead of the intended 3-attempt backoff.
    """

    def _make(self):
        return SessionCortexApi(
            "http://cortex.invalid:9001", "k", proxies={"http": "", "https": ""}
        )

    def test_5xx_from_cortex_is_retried_by_RETRY_and_succeeds(self):
        api = self._make()
        api._session = MagicMock()

        call_count = 0

        def fake_request(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                resp = MagicMock()
                resp.status_code = 500
                resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
                return resp
            ok = MagicMock()
            ok.raise_for_status.return_value = None
            return ok

        api._session.request.side_effect = fake_request

        @RETRY
        def call_it():
            return api.do_get("job/xyz/report")

        with patch("tenacity.nap.time.sleep"):
            call_it()

        self.assertEqual(call_count, 3)
