from unittest.mock import MagicMock

from django.test import TestCase

from common.http_client import TimeoutHTTPAdapter
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
        # cortex4py's Api builds base_url as "{url}/api/" — endpoints
        # in controllers are passed without a leading slash.
        self.assertEqual(args[1], "http://cortex.invalid:9001/api/status")
        self.assertIn("Authorization", kwargs["headers"])
        self.assertTrue(kwargs["headers"]["Authorization"].startswith("Bearer "))
