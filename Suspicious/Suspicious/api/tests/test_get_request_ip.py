from django.test import SimpleTestCase

from api.views.downloads import get_request_ip


class _Req:
    def __init__(self, meta):
        self.META = meta


class GetRequestIpTests(SimpleTestCase):
    def test_uses_rightmost_forwarded_for_not_client_supplied(self):
        req = _Req({"HTTP_X_FORWARDED_FOR": "9.9.9.9, 10.0.0.1, 203.0.113.7"})
        self.assertEqual(get_request_ip(req), "203.0.113.7")

    def test_single_forwarded_for(self):
        req = _Req({"HTTP_X_FORWARDED_FOR": "203.0.113.7"})
        self.assertEqual(get_request_ip(req), "203.0.113.7")

    def test_falls_back_to_remote_addr(self):
        req = _Req({"REMOTE_ADDR": "198.51.100.4"})
        self.assertEqual(get_request_ip(req), "198.51.100.4")
