from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient


class AIModelRunsPermissionTest(TestCase):
    """GET is open to any authenticated user; POST stays gated to the
    ml-retrain service account / staff."""

    def setUp(self):
        self.url = reverse("ai-model-runs")
        self.user = User.objects.create_user("plain@example.com", password="x")

    def test_anonymous_cannot_read(self):
        self.assertIn(APIClient().get(self.url).status_code, (401, 403))

    def test_plain_authenticated_user_can_read(self):
        client = APIClient()
        client.force_authenticate(self.user)
        self.assertEqual(client.get(self.url).status_code, 200)

    def test_plain_authenticated_user_cannot_post(self):
        client = APIClient()
        client.force_authenticate(self.user)
        self.assertEqual(client.post(self.url, {}, format="json").status_code, 403)
