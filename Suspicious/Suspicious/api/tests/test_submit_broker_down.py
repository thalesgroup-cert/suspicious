from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TransactionTestCase, override_settings
from kombu.exceptions import OperationalError
from rest_framework.test import APIClient


@override_settings(ROOT_URLCONF="suspicious.urls")
class SubmitBrokerDownTests(TransactionTestCase):
    """TransactionTestCase: the URL path dispatches in transaction.on_commit."""

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(User.objects.create_user("u", password="pw-12345"))

    def _down(self, target):
        return patch(target, side_effect=OperationalError("down"))

    def test_url_submit_returns_503(self):
        with self._down("tasp.tasks.dispatch_case_analysis.delay"):
            resp = self.client.post("/api/submit/url/", {"url": "http://evil-example.com/x"}, format="json")
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()["code"], "broker_unavailable")
        self.assertEqual(resp["Retry-After"], "30")

    def test_indicators_submit_returns_503(self):
        with self._down("api.views.submit.dispatch_case_analysis.delay"):
            resp = self.client.post("/api/submit/indicators/", {"indicators": "8.8.8.8"}, format="json")
        self.assertEqual(resp.status_code, 503)
