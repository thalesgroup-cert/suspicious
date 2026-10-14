from django.contrib.auth.models import User
from django.test import override_settings
from rest_framework.test import APITestCase

from api.views.submit import IOC_GROUP_MAX

URL = "/api/submit/config/"


class SubmitConfigLimitsTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user("cfg@example.com", password="x")

    def test_limits_present(self):
        from django.conf import settings
        self.client.force_authenticate(self.user)
        data = self.client.get(URL).json()["data"]
        self.assertEqual(data["max_file_bytes"], settings.SUBMIT_FILE_MAX_BYTES)
        self.assertEqual(data["max_indicators"], IOC_GROUP_MAX)
        self.assertEqual(data["max_indicators"], 100)

    @override_settings(SUBMIT_FILE_MAX_BYTES=1234)
    def test_file_limit_follows_settings(self):
        self.client.force_authenticate(self.user)
        self.assertEqual(self.client.get(URL).json()["data"]["max_file_bytes"], 1234)

    def test_unauthenticated_rejected(self):
        self.assertIn(self.client.get(URL).status_code, (401, 403))
