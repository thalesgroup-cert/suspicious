from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token  # noqa: F401 (import style parity)

User = get_user_model()


class AvatarAppearanceTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw12345!")
        self.client.force_authenticate(user=self.user)
        self.url = "/api/profile/appearance/"

    def test_valid_avatar_saves_and_roundtrips(self):
        resp = self.client.patch(
            self.url, {"avatar": {"style": "bottts", "seed": "abc123"}}, format="json"
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["avatar"], {"style": "bottts", "seed": "abc123"})

        get = self.client.get("/api/profile/")
        self.assertEqual(get.data["avatar"], {"style": "bottts", "seed": "abc123"})

    def test_unknown_style_rejected(self):
        resp = self.client.patch(
            self.url, {"avatar": {"style": "not-a-style", "seed": "x"}}, format="json"
        )
        self.assertEqual(resp.status_code, 400)

    def test_oversized_seed_rejected(self):
        resp = self.client.patch(
            self.url, {"avatar": {"style": "bottts", "seed": "z" * 65}}, format="json"
        )
        self.assertEqual(resp.status_code, 400)

    def test_non_string_seed_rejected(self):
        resp = self.client.patch(
            self.url, {"avatar": {"style": "bottts", "seed": 42}}, format="json"
        )
        self.assertEqual(resp.status_code, 400)

    def test_empty_object_clears_avatar(self):
        self.client.patch(
            self.url, {"avatar": {"style": "bottts", "seed": "abc123"}}, format="json"
        )
        resp = self.client.patch(self.url, {"avatar": {}}, format="json")
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["avatar"], {})

    def test_valid_options_saves_and_roundtrips(self):
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123",
                        "options": {"eyes": ["happy"]}}},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(
            resp.data["avatar"],
            {"style": "avataaars", "seed": "abc123", "options": {"eyes": ["happy"]}},
        )
        get = self.client.get("/api/profile/")
        self.assertEqual(get.data["avatar"]["options"], {"eyes": ["happy"]})

    def test_string_option_value_is_normalised_to_list(self):
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123",
                        "options": {"eyes": "happy"}}},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["avatar"]["options"], {"eyes": ["happy"]})

    def test_too_many_option_keys_rejected(self):
        opts = {f"k{i}": ["v"] for i in range(21)}
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123", "options": opts}},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_oversized_option_value_rejected(self):
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123",
                        "options": {"eyes": ["z" * 65]}}},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_non_string_option_value_rejected(self):
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123",
                        "options": {"eyes": [42]}}},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_empty_options_are_dropped(self):
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123", "options": {}}},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["avatar"], {"style": "avataaars", "seed": "abc123"})
