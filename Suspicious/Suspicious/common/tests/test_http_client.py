import unittest
from unittest.mock import MagicMock, patch

import requests
from requests.adapters import HTTPAdapter


class TestTimeoutHTTPAdapter(unittest.TestCase):
    """TimeoutHTTPAdapter injects a default timeout and respects explicit overrides."""

    def _make_adapter(self):
        from common.http_client import TimeoutHTTPAdapter
        return TimeoutHTTPAdapter(connect_timeout=3, read_timeout=10)

    def test_injects_default_timeout_when_none_passed(self):
        """When the caller passes no timeout kwarg, adapter injects (connect, read)."""
        adapter = self._make_adapter()
        captured = {}

        def fake_send(prepared_request, **kwargs):
            captured.update(kwargs)
            return MagicMock(status_code=200)

        with patch.object(HTTPAdapter, "send", side_effect=fake_send):
            adapter.send(MagicMock())

        self.assertEqual(captured.get("timeout"), (3, 10))

    def test_respects_caller_supplied_timeout(self):
        """When the caller passes an explicit timeout, adapter does NOT override it."""
        adapter = self._make_adapter()
        captured = {}

        def fake_send(prepared_request, **kwargs):
            captured.update(kwargs)
            return MagicMock(status_code=200)

        with patch.object(HTTPAdapter, "send", side_effect=fake_send):
            adapter.send(MagicMock(), timeout=(1, 2))

        self.assertEqual(captured.get("timeout"), (1, 2))

    def test_default_values_are_5_and_30(self):
        """Default connect=5, read=30 when no custom values passed."""
        from common.http_client import TimeoutHTTPAdapter, DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT
        adapter = TimeoutHTTPAdapter()
        self.assertEqual(adapter.connect_timeout, DEFAULT_CONNECT_TIMEOUT)
        self.assertEqual(adapter.read_timeout, DEFAULT_READ_TIMEOUT)
        self.assertEqual(DEFAULT_CONNECT_TIMEOUT, 5)
        self.assertEqual(DEFAULT_READ_TIMEOUT, 30)


class TestMakeSession(unittest.TestCase):
    """make_session() returns a requests.Session with TimeoutHTTPAdapter mounted."""

    def _make(self, **kwargs):
        from common.http_client import make_session
        return make_session(**kwargs)

    def test_returns_requests_session(self):
        self.assertIsInstance(self._make(), requests.Session)

    def test_adapter_mounted_on_https(self):
        from common.http_client import TimeoutHTTPAdapter
        session = self._make()
        self.assertIsInstance(session.get_adapter("https://example.com"), TimeoutHTTPAdapter)

    def test_adapter_mounted_on_http(self):
        from common.http_client import TimeoutHTTPAdapter
        session = self._make()
        self.assertIsInstance(session.get_adapter("http://example.com"), TimeoutHTTPAdapter)

    def test_custom_timeouts_flow_to_adapter(self):
        session = self._make(connect_timeout=2, read_timeout=15)
        adapter = session.get_adapter("https://example.com")
        self.assertEqual(adapter.connect_timeout, 2)
        self.assertEqual(adapter.read_timeout, 15)


class TestBreakers(unittest.TestCase):
    """BREAKERS dict has one CircuitBreaker per integration, correctly configured."""

    def test_all_four_integrations_present(self):
        from common.http_client import BREAKERS
        for name in ("cortex", "thehive", "misp", "virustotal"):
            self.assertIn(name, BREAKERS, f"Missing breaker for {name!r}")

    def test_breaker_fail_max_and_reset_timeout(self):
        from common.http_client import BREAKERS, BREAKER_FAIL_MAX, BREAKER_RESET_TIMEOUT
        self.assertEqual(BREAKER_FAIL_MAX, 5)
        self.assertEqual(BREAKER_RESET_TIMEOUT, 60)
        for name, breaker in BREAKERS.items():
            self.assertEqual(breaker.fail_max, BREAKER_FAIL_MAX, name)
            self.assertEqual(breaker.reset_timeout, BREAKER_RESET_TIMEOUT, name)

    def test_get_breaker_returns_same_instance(self):
        from common.http_client import BREAKERS, get_breaker
        self.assertIs(get_breaker("thehive"), BREAKERS["thehive"])

    def test_get_breaker_creates_unknown_name_on_demand(self):
        from common.http_client import get_breaker
        b1 = get_breaker("some_new_connector")
        b2 = get_breaker("some_new_connector")
        self.assertIs(b1, b2)

    def test_ensure_breaker_is_idempotent(self):
        from common.http_client import ensure_breaker, BREAKERS
        b1 = ensure_breaker("another_connector")
        b2 = ensure_breaker("another_connector")
        self.assertIs(b1, b2)
        self.assertIn("another_connector", BREAKERS)


class TestRetryDecorator(unittest.TestCase):
    """RETRY retries on ConnectionError/Timeout/5xx but not 4xx."""

    def test_retries_on_connection_error_and_succeeds(self):
        from common.http_client import RETRY
        call_count = 0

        @RETRY
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise requests.ConnectionError("down")
            return "ok"

        with patch("tenacity.nap.time.sleep"):
            result = flaky()

        self.assertEqual(result, "ok")
        self.assertEqual(call_count, 3)

    def test_raises_after_three_failed_attempts(self):
        from common.http_client import RETRY
        call_count = 0

        @RETRY
        def always_fails():
            nonlocal call_count
            call_count += 1
            raise requests.ConnectionError("always down")

        with patch("tenacity.nap.time.sleep"):
            with self.assertRaises(requests.ConnectionError):
                always_fails()

        self.assertEqual(call_count, 3)

    def test_does_not_retry_on_4xx(self):
        from common.http_client import RETRY
        call_count = 0

        @RETRY
        def client_error():
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 404
            raise requests.HTTPError(response=resp)

        with patch("tenacity.nap.time.sleep"):
            with self.assertRaises(requests.HTTPError):
                client_error()

        self.assertEqual(call_count, 1)

    def test_retries_on_5xx_and_succeeds(self):
        from common.http_client import RETRY
        call_count = 0

        @RETRY
        def server_error():
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 503
            if call_count < 3:
                raise requests.HTTPError(response=resp)
            return "ok"

        with patch("tenacity.nap.time.sleep"):
            result = server_error()

        self.assertEqual(result, "ok")
        self.assertEqual(call_count, 3)

    def test_retries_on_timeout(self):
        from common.http_client import RETRY
        call_count = 0

        @RETRY
        def timeout_once():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise requests.Timeout("timed out")
            return "ok"

        with patch("tenacity.nap.time.sleep"):
            result = timeout_once()

        self.assertEqual(result, "ok")
        self.assertEqual(call_count, 2)
