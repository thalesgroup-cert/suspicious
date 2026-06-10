import json
import pathlib
import tempfile
import unittest
from unittest import mock

import classes.services.config_service as cs


_API_RESPONSE = {
    "storage": {"s3": {"endpoint": "rustfs:9000", "access_key": "AK",
                       "secret_key": "SK", "secure": False}},
    "email": {"smtp": {"server": "smtp.local", "port": 25,
                       "username": "u", "password": "PW", "tls": True}},
    "branding": {"company_name": "Acme"},
}

_LOCAL = {
    "mail-connectors": {"imap": {}, "imaps": {}},
    "working-path": "/tmp/suspicious",
    "timer-inbox-emails": 10,
}


class FeederConfigApiTest(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.local = self.dir / "config.json"
        self.local.write_text(json.dumps(_LOCAL))
        self.cache = self.dir / ".config-cache.json"

    def _resp(self, status=200, body=None):
        m = mock.Mock()
        m.status_code = status
        m.json.return_value = body if body is not None else _API_RESPONSE
        m.raise_for_status.side_effect = None if status == 200 else Exception("http")
        return m

    def test_maps_api_response_to_main_config(self):
        with mock.patch.object(cs.requests, "get", return_value=self._resp()):
            mc = cs.load_config_from_api("http://backend:9020", "tok",
                                         self.local, self.cache)
        self.assertEqual(mc.minio.endpoint, "rustfs:9000")
        self.assertEqual(mc.minio.secret_key, "SK")
        self.assertEqual(str(mc.working_path), "/tmp/suspicious")
        self.assertTrue(self.cache.exists())

    def test_falls_back_to_cache_when_backend_down(self):
        with mock.patch.object(cs.requests, "get", return_value=self._resp()):
            cs.load_config_from_api("http://backend:9020", "tok", self.local, self.cache)
        with mock.patch.object(cs.requests, "get", side_effect=Exception("conn")):
            mc = cs.load_config_from_api("http://backend:9020", "tok",
                                         self.local, self.cache, retries=1, backoff=0)
        self.assertEqual(mc.minio.endpoint, "rustfs:9000")

    def test_fail_fast_when_no_cache_and_backend_down(self):
        with mock.patch.object(cs.requests, "get", side_effect=Exception("conn")):
            with self.assertRaises(Exception):
                cs.load_config_from_api("http://backend:9020", "tok",
                                        self.local, self.cache, retries=1, backoff=0)
