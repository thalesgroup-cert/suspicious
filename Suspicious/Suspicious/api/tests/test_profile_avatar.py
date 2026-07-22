from unittest import mock

from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token  # noqa: F401 (import style parity)

from profiles.profiles_utils.avatar_storage import AVATAR_MAX_BYTES

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


class AvatarUploadStyleRejectedViaAppearanceTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="bob", password="pw12345!")
        self.client.force_authenticate(user=self.user)

    def test_upload_style_rejected_via_appearance_patch(self):
        resp = self.client.patch(
            "/api/profile/appearance/",
            {"avatar": {"style": "upload", "seed": "avatars/1/x.jpg"}},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)


class AvatarValidationViaProfileEndpointTests(APITestCase):
    """PATCH /api/profile/ must apply the same AvatarField validation as
    PATCH /profile/appearance/ — regression test for the bypass where
    UserProfileSerializer/CISOProfileSerializer listed "avatar" in
    Meta.fields without an explicit AvatarField, so DRF auto-generated an
    unvalidated bare JSONField."""

    def setUp(self):
        self.user = User.objects.create_user(username="dave", password="pw12345!")
        self.client.force_authenticate(user=self.user)
        self.url = "/api/profile/"

    def test_upload_style_rejected_via_profile_patch(self):
        resp = self.client.patch(
            self.url, {"avatar": {"style": "upload", "seed": "x"}}, format="json"
        )
        self.assertEqual(resp.status_code, 400, resp.content)

    def test_valid_avatar_accepted_via_profile_patch(self):
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123"}},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["avatar"], {"style": "avataaars", "seed": "abc123"})


class AvatarPresignedUrlExpansionTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="carol", password="pw12345!")
        self.client.force_authenticate(user=self.user)

    def test_get_profile_expands_upload_avatar_to_presigned_url(self):
        from profiles.models import UserProfile
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.avatar = {"style": "upload", "seed": "avatars/1/abc.jpg"}
        profile.save(update_fields=["avatar"])

        with mock.patch(
            "api.serializers.profile.presigned_avatar_url",
            return_value="https://rustfs/signed-url",
        ):
            resp = self.client.get("/api/profile/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["avatar"]["style"], "upload")
        self.assertEqual(resp.data["avatar"]["seed"], "avatars/1/abc.jpg")
        self.assertEqual(resp.data["avatar"]["url"], "https://rustfs/signed-url")

    def test_get_profile_omits_url_when_presign_fails(self):
        from profiles.models import UserProfile
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.avatar = {"style": "upload", "seed": "avatars/1/abc.jpg"}
        profile.save(update_fields=["avatar"])

        with mock.patch(
            "api.serializers.profile.presigned_avatar_url", return_value=None
        ):
            resp = self.client.get("/api/profile/")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("url", resp.data["avatar"])


import io
import os
from PIL import Image


def _jpeg_upload(width=300, height=300, name="photo.jpg", content_type="image/jpeg"):
    from django.core.files.uploadedfile import SimpleUploadedFile
    buf = io.BytesIO()
    # ponytail: random noise (not a solid fill) so JPEG compression can't
    # shrink a "big" image back under AVATAR_MAX_BYTES — a solid-color
    # 3000x3000 JPEG compresses to ~140KB, which would silently defeat
    # test_oversized_upload_rejected_without_storage_call.
    raw = os.urandom(width * height * 3)
    Image.frombytes("RGB", (width, height), raw).save(buf, format="JPEG")
    return SimpleUploadedFile(name, buf.getvalue(), content_type=content_type)


class AvatarUploadEndpointTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="dave", password="pw12345!")
        self.client.force_authenticate(user=self.user)
        self.url = "/api/profile/avatar/upload/"

    def test_upload_sets_avatar_style_and_seed(self):
        fake_client = mock.MagicMock()
        fake_client.bucket_exists.return_value = True
        fake_client.presigned_get_object.return_value = "https://rustfs/signed"
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ):
            resp = self.client.post(
                self.url, {"avatar": _jpeg_upload()}, format="multipart"
            )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["avatar"]["style"], "upload")
        self.assertTrue(resp.data["avatar"]["seed"].startswith(f"avatars/{self.user.id}/"))
        self.assertEqual(resp.data["avatar"]["url"], "https://rustfs/signed")
        fake_client.put_object.assert_called_once()

    def test_oversized_upload_rejected_without_storage_call(self):
        fake_client = mock.MagicMock()
        big = _jpeg_upload(width=3000, height=3000)
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ):
            resp = self.client.post(self.url, {"avatar": big}, format="multipart")
        if resp.status_code == 200:
            self.fail("expected rejection for an oversized upload")
        self.assertEqual(resp.status_code, 400)
        fake_client.put_object.assert_not_called()

    def test_oversized_upload_rejected_before_read(self):
        """The view must reject on declared .size alone, before ever calling
        process_avatar_image or upload.read(). Uses a mock upload (tiny
        actual body, oversized declared .size) so the assertion holds
        regardless of what a real multipart parser would report — going
        through the test client would re-derive .size from actual bytes
        transmitted, defeating the point of this test, so the view is
        invoked directly instead."""
        from api.views.profile import AvatarUploadView

        fake_upload = mock.MagicMock()
        fake_upload.content_type = "image/jpeg"
        fake_upload.size = AVATAR_MAX_BYTES + 1
        fake_upload.read = mock.MagicMock(
            side_effect=AssertionError("upload.read() must not be called before the size gate")
        )

        request = mock.MagicMock()
        request.FILES = {"avatar": fake_upload}
        request.user = self.user

        with mock.patch("api.views.profile.process_avatar_image") as mock_process:
            resp = AvatarUploadView().post(request)

        self.assertEqual(resp.status_code, 400)
        self.assertIn(str(AVATAR_MAX_BYTES), resp.data["detail"])
        mock_process.assert_not_called()
        fake_upload.read.assert_not_called()

    def test_corrupt_file_rejected(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        bad = SimpleUploadedFile("photo.jpg", b"not-an-image", content_type="image/jpeg")
        fake_client = mock.MagicMock()
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ):
            resp = self.client.post(self.url, {"avatar": bad}, format="multipart")
        self.assertEqual(resp.status_code, 400)
        fake_client.put_object.assert_not_called()

    def test_no_file_provided(self):
        resp = self.client.post(self.url, {}, format="multipart")
        self.assertEqual(resp.status_code, 400)

    def test_reupload_deletes_previous_object(self):
        from profiles.models import UserProfile
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.avatar = {"style": "upload", "seed": "avatars/1/old.jpg"}
        profile.save(update_fields=["avatar"])

        fake_client = mock.MagicMock()
        fake_client.bucket_exists.return_value = True
        fake_client.presigned_get_object.return_value = "https://rustfs/signed"
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ):
            resp = self.client.post(
                self.url, {"avatar": _jpeg_upload()}, format="multipart"
            )
        self.assertEqual(resp.status_code, 200, resp.content)
        fake_client.remove_object.assert_called_once_with(
            "suspicious-avatars", "avatars/1/old.jpg"
        )

    def test_upload_works_for_ciso_profile(self):
        from profiles.models import CISOProfile
        CISOProfile.objects.get_or_create(
            user=self.user,
            defaults={"function": "f", "gbu": "g", "country": "c", "region": "r"},
        )
        fake_client = mock.MagicMock()
        fake_client.bucket_exists.return_value = True
        fake_client.presigned_get_object.return_value = "https://rustfs/signed"
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ):
            resp = self.client.post(
                self.url, {"avatar": _jpeg_upload()}, format="multipart"
            )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["avatar"]["style"], "upload")
