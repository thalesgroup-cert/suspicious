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
