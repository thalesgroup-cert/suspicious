"""
Tests for connectors.contrib.thehive.phishing

Patches _thehive_request directly — retry/breaker behaviour is tested
separately in common/tests/test_http_client.py.
"""
import sys
import unittest
from unittest.mock import MagicMock, patch

import pybreaker
import requests


# ---------------------------------------------------------------------------
# Stub out heavy / unavailable dependencies before any import of phishing.py
# ---------------------------------------------------------------------------

# Stub pydantic (not installed in test environment)
_pydantic_stub = MagicMock()
sys.modules.setdefault("pydantic", _pydantic_stub)

# Stub the utils / models sub-modules so we don't need pydantic at all
_utils_stub = MagicMock()
_models_stub = MagicMock()
sys.modules.setdefault("connectors.contrib.thehive.utils", _utils_stub)
sys.modules.setdefault("connectors.contrib.thehive.models", _models_stub)

_FAKE_THEHIVE_CONFIG = {"certificate_path": None, "user": "admin"}


def _patch_thehive_config():
    """Return a context manager that stubs _thehive_config()."""
    return patch(
        "connectors.contrib.thehive.phishing._thehive_config",
        return_value=_FAKE_THEHIVE_CONFIG,
    )


# ---------------------------------------------------------------------------
# Helper: import phishing (no open() needed — module-level is now lazy)
# ---------------------------------------------------------------------------

def _import_phishing():
    # Remove cached module so a clean import occurs
    for key in list(sys.modules):
        if "phishing" in key and "test" not in key:
            del sys.modules[key]
    import connectors.contrib.thehive.phishing as ph
    return ph


# Pre-import once so subsequent test-method imports are cheap
import connectors.contrib.thehive.phishing  # noqa: F401 — side-effect import


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCreateNewAlert(unittest.TestCase):

    def setUp(self):
        p = patch(
            "connectors.contrib.thehive.phishing._thehive_config",
            return_value=_FAKE_THEHIVE_CONFIG,
        )
        p.start()
        self.addCleanup(p.stop)

    def _call(self, **overrides):
        from connectors.contrib.thehive.phishing import create_new_alert
        kwargs = dict(
            ticket_id="REF-001",
            title="Test alert",
            description="Desc",
            severity=2,
            tlp=1,
            pap=1,
            app_name="suspicious",
            thehive_url="https://hive.local",
            api_key="key123",
        )
        kwargs.update(overrides)
        return create_new_alert(**kwargs)

    def test_returns_alert_dict_on_success(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"_id": "~alert42"}

        with patch("connectors.contrib.thehive.phishing._thehive_request", return_value=mock_resp):
            result = self._call()

        self.assertEqual(result, {"_id": "~alert42"})

    def test_returns_none_on_request_exception(self):
        with patch(
            "connectors.contrib.thehive.phishing._thehive_request",
            side_effect=requests.ConnectionError("down"),
        ):
            result = self._call()

        self.assertIsNone(result)

    def test_returns_none_on_circuit_breaker_open(self):
        with patch(
            "connectors.contrib.thehive.phishing._thehive_request",
            side_effect=pybreaker.CircuitBreakerError(),
        ):
            result = self._call()

        self.assertIsNone(result)

    def test_auto_generates_ticket_id_when_none(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"_id": "~auto"}

        with patch("connectors.contrib.thehive.phishing._thehive_request", return_value=mock_resp):
            result = self._call(ticket_id=None)

        self.assertEqual(result, {"_id": "~auto"})


class TestGetItemFromId(unittest.TestCase):

    def setUp(self):
        p = patch(
            "connectors.contrib.thehive.phishing._thehive_config",
            return_value=_FAKE_THEHIVE_CONFIG,
        )
        p.start()
        self.addCleanup(p.stop)

    def _call(self, item_id="~42"):
        from connectors.contrib.thehive.phishing import get_item_from_id
        return get_item_from_id(item_id, "https://hive.local", "key123")

    def test_returns_case_type_and_data(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"_id": "~42", "title": "case"}

        with patch("connectors.contrib.thehive.phishing._thehive_request", return_value=mock_resp):
            item_type, data = self._call()

        self.assertEqual(item_type, "case")
        self.assertEqual(data["_id"], "~42")

    def test_returns_none_none_when_not_found(self):
        err = requests.HTTPError()
        err.response = MagicMock(status_code=404)

        with patch("connectors.contrib.thehive.phishing._thehive_request", side_effect=err):
            item_type, data = self._call()

        self.assertIsNone(item_type)
        self.assertIsNone(data)

    def test_returns_none_none_on_breaker_open(self):
        with patch(
            "connectors.contrib.thehive.phishing._thehive_request",
            side_effect=pybreaker.CircuitBreakerError(),
        ):
            item_type, data = self._call()

        self.assertIsNone(item_type)
        self.assertIsNone(data)


class TestAddObservablesToItem(unittest.TestCase):

    def setUp(self):
        p = patch(
            "connectors.contrib.thehive.phishing._thehive_config",
            return_value=_FAKE_THEHIVE_CONFIG,
        )
        p.start()
        self.addCleanup(p.stop)

    def _call(self):
        from connectors.contrib.thehive.phishing import add_observables_to_item
        return add_observables_to_item(
            "alert", "~42", [{"dataType": "url", "data": "http://evil.test"}],
            "https://hive.local", "key123",
        )

    def test_posts_each_observable(self):
        mock_resp = MagicMock()
        with patch("connectors.contrib.thehive.phishing._thehive_request", return_value=mock_resp) as mock_req:
            self._call()
        self.assertEqual(mock_req.call_count, 1)

    def test_skips_invalid_item_type(self):
        from connectors.contrib.thehive.phishing import add_observables_to_item
        with patch("connectors.contrib.thehive.phishing._thehive_request") as mock_req:
            add_observables_to_item("invalid", "~42", [{}], "https://hive.local", "key123")
        mock_req.assert_not_called()


class TestAddAttachmentsToItem(unittest.TestCase):

    def setUp(self):
        p = patch(
            "connectors.contrib.thehive.phishing._thehive_config",
            return_value=_FAKE_THEHIVE_CONFIG,
        )
        p.start()
        self.addCleanup(p.stop)

    def test_posts_attachment_successfully(self):
        from connectors.contrib.thehive.phishing import add_attachments_to_item
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test content")
            tmp_path = f.name

        try:
            mock_resp = MagicMock()
            with patch("connectors.contrib.thehive.phishing._thehive_request", return_value=mock_resp) as mock_req:
                add_attachments_to_item("alert", "~42", [tmp_path], "https://hive.local", "key123")
            self.assertEqual(mock_req.call_count, 1)
            call_args = mock_req.call_args
            self.assertEqual(call_args[0][0], "POST")
        finally:
            os.unlink(tmp_path)

    def test_stops_on_circuit_breaker_open(self):
        from connectors.contrib.thehive.phishing import add_attachments_to_item
        import tempfile
        import os

        # Create two temp files — only one POST should be attempted before breaker stops loop
        paths = []
        for _ in range(2):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
                f.write(b"x")
                paths.append(f.name)

        try:
            with patch(
                "connectors.contrib.thehive.phishing._thehive_request",
                side_effect=pybreaker.CircuitBreakerError(),
            ) as mock_req:
                add_attachments_to_item("alert", "~42", paths, "https://hive.local", "key123")
            # Loop should exit after first breaker-open — only 1 attempt
            self.assertEqual(mock_req.call_count, 1)
        finally:
            for p in paths:
                os.unlink(p)

    def test_skips_invalid_item_type(self):
        from connectors.contrib.thehive.phishing import add_attachments_to_item
        with patch("connectors.contrib.thehive.phishing._thehive_request") as mock_req:
            add_attachments_to_item("invalid", "~42", ["/tmp/x.txt"], "https://hive.local", "key")
        mock_req.assert_not_called()


class TestAddCommentToItem(unittest.TestCase):

    def setUp(self):
        p = patch(
            "connectors.contrib.thehive.phishing._thehive_config",
            return_value=_FAKE_THEHIVE_CONFIG,
        )
        p.start()
        self.addCleanup(p.stop)

    def _call(self, **overrides):
        from connectors.contrib.thehive.phishing import add_comment_to_item
        kwargs = dict(
            item_type="alert",
            item_id="~42",
            comment={"message": "test comment"},
            thehive_url="https://hive.local",
            api_key="key123",
        )
        kwargs.update(overrides)
        return add_comment_to_item(**kwargs)

    def test_posts_new_comment_when_no_existing(self):
        # Query returns empty list → POST new comment
        responses = [
            MagicMock(**{"json.return_value": []}),  # query response
            MagicMock(),  # POST new comment
        ]
        with patch(
            "connectors.contrib.thehive.phishing._thehive_request",
            side_effect=responses,
        ) as mock_req:
            self._call()
        self.assertEqual(mock_req.call_count, 2)
        # Second call should be POST to add_comment URL
        second_call = mock_req.call_args_list[1]
        self.assertEqual(second_call[0][0], "POST")

    def test_patches_existing_recent_comment(self):
        import time
        existing = {
            "_id": "comment1",
            "createdAt": int(time.time() * 1000) - 1000,  # 1 second ago — recent
            "createdBy": "suspicious",  # match thehive_config user
        }
        responses = [
            MagicMock(**{"json.return_value": [existing]}),
            MagicMock(),
        ]
        # Patch _thehive_config to return matching user
        with patch("connectors.contrib.thehive.phishing._thehive_config", return_value={"user": "suspicious"}):
            with patch(
                "connectors.contrib.thehive.phishing._thehive_request",
                side_effect=responses,
            ) as mock_req:
                self._call()
        self.assertEqual(mock_req.call_count, 2)
        # Second call should be PATCH
        second_call = mock_req.call_args_list[1]
        self.assertEqual(second_call[0][0], "PATCH")

    def test_circuit_breaker_open_skips_silently(self):
        with patch(
            "connectors.contrib.thehive.phishing._thehive_request",
            side_effect=pybreaker.CircuitBreakerError(),
        ):
            # Should not raise
            self._call()

    def test_request_exception_triggers_fallback_post(self):
        # Query fails → fallback POST fires
        fallback_resp = MagicMock()
        with patch(
            "connectors.contrib.thehive.phishing._thehive_request",
            side_effect=[requests.ConnectionError("query failed"), fallback_resp],
        ) as mock_req:
            self._call()
        self.assertEqual(mock_req.call_count, 2)
        # Second call must be POST
        second_call = mock_req.call_args_list[1]
        self.assertEqual(second_call[0][0], "POST")

    def test_fallback_post_breaker_open_no_crash(self):
        # Query fails, then breaker open on fallback — must not raise
        with patch(
            "connectors.contrib.thehive.phishing._thehive_request",
            side_effect=[
                requests.ConnectionError("query failed"),
                pybreaker.CircuitBreakerError(),
            ],
        ):
            self._call()  # must not raise

    def test_skips_invalid_item_type(self):
        with patch("connectors.contrib.thehive.phishing._thehive_request") as mock_req:
            self._call(item_type="invalid")
        mock_req.assert_not_called()
