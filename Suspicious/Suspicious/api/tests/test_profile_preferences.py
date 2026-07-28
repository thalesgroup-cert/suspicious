from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

User = get_user_model()


class SidebarPinnedPreferenceTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw12345!")
        self.client.force_authenticate(user=self.user)
        self.url = "/api/profile/preferences/"

    def test_defaults_to_unpinned(self):
        resp = self.client.get("/api/profile/")
        self.assertEqual(resp.data["sidebar_pinned"], False)

    def test_pin_roundtrips(self):
        resp = self.client.patch(self.url, {"sidebar_pinned": True}, format="json")
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["sidebar_pinned"], True)

        get = self.client.get("/api/profile/")
        self.assertEqual(get.data["sidebar_pinned"], True)
