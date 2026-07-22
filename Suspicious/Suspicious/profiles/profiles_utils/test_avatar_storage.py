import io
from unittest import mock

from django.test import SimpleTestCase
from PIL import Image

from profiles.profiles_utils.avatar_storage import (
    AVATAR_DIMENSION,
    InvalidAvatarImage,
    delete_avatar,
    presigned_avatar_url,
    process_avatar_image,
    store_avatar,
)


def _jpeg_bytes(width=800, height=400, color=(255, 0, 0)):
    buf = io.BytesIO()
    Image.new("RGB", (width, height), color).save(buf, format="JPEG")
    return buf.getvalue()


class ProcessAvatarImageTest(SimpleTestCase):
    def test_rejects_unsupported_content_type(self):
        with self.assertRaises(InvalidAvatarImage):
            process_avatar_image("image/gif", 100, b"whatever")

    def test_rejects_oversized_file(self):
        raw = _jpeg_bytes()
        with self.assertRaises(InvalidAvatarImage):
            process_avatar_image("image/jpeg", 3 * 1024 * 1024, raw)

    def test_rejects_corrupt_file_with_valid_content_type(self):
        with self.assertRaises(InvalidAvatarImage):
            process_avatar_image("image/jpeg", 10, b"not-an-image")

    def test_valid_jpeg_is_cropped_to_square_and_resized(self):
        raw = _jpeg_bytes(width=800, height=400)
        out = process_avatar_image("image/jpeg", len(raw), raw)
        img = Image.open(io.BytesIO(out))
        self.assertEqual(img.size, (AVATAR_DIMENSION, AVATAR_DIMENSION))
        self.assertEqual(img.format, "JPEG")

    def test_valid_png_is_accepted_and_reencoded_as_jpeg(self):
        buf = io.BytesIO()
        Image.new("RGB", (300, 300), (0, 255, 0)).save(buf, format="PNG")
        raw = buf.getvalue()
        out = process_avatar_image("image/png", len(raw), raw)
        img = Image.open(io.BytesIO(out))
        self.assertEqual(img.format, "JPEG")

    def test_exif_is_not_preserved(self):
        buf = io.BytesIO()
        img = Image.new("RGB", (300, 300), (0, 0, 255))
        exif = img.getexif()
        exif[0x9286] = "some comment"  # UserComment tag
        img.save(buf, format="JPEG", exif=exif)
        raw = buf.getvalue()
        out = process_avatar_image("image/jpeg", len(raw), raw)
        out_img = Image.open(io.BytesIO(out))
        self.assertEqual(dict(out_img.getexif()), {})

    def test_decompression_bomb_raises_invalid_avatar_image(self):
        # A real bomb file has huge declared dimensions but a tiny byte
        # size (a solid color compresses to almost nothing) — Pillow's
        # guard fires off the declared header size, not actual decoded
        # memory, so we don't need to allocate a giant image here: lower
        # MAX_IMAGE_PIXELS instead so an ordinary small image trips it.
        raw = _jpeg_bytes(width=300, height=300)
        with mock.patch.object(Image, "MAX_IMAGE_PIXELS", 100):
            with self.assertRaises(InvalidAvatarImage):
                process_avatar_image("image/jpeg", len(raw), raw)


class StoreAvatarTest(SimpleTestCase):
    def test_store_avatar_uploads_and_returns_key(self):
        fake_client = mock.MagicMock()
        fake_client.bucket_exists.return_value = True
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ):
            key = store_avatar(42, b"jpegbytes")
        self.assertTrue(key.startswith("avatars/42/"))
        self.assertTrue(key.endswith(".jpg"))
        fake_client.put_object.assert_called_once()
        call = fake_client.put_object.call_args
        self.assertEqual(call.args[0], "suspicious-avatars")
        self.assertEqual(call.args[1], key)

    def test_store_avatar_creates_bucket_if_missing(self):
        fake_client = mock.MagicMock()
        fake_client.bucket_exists.return_value = False
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ):
            store_avatar(1, b"bytes")
        fake_client.make_bucket.assert_called_once_with("suspicious-avatars")

    def test_store_avatar_uses_configured_bucket_name(self):
        fake_client = mock.MagicMock()
        fake_client.bucket_exists.return_value = True
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ), mock.patch(
            "profiles.profiles_utils.avatar_storage.get_section",
            return_value={"avatars_bucket": "custom-bucket"},
        ):
            store_avatar(42, b"jpegbytes")
        # Verify that custom-bucket was used, not the default
        call = fake_client.put_object.call_args
        self.assertEqual(call.args[0], "custom-bucket")


class DeleteAvatarTest(SimpleTestCase):
    def test_delete_avatar_calls_remove_object(self):
        fake_client = mock.MagicMock()
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ):
            delete_avatar("avatars/1/abc.jpg")
        fake_client.remove_object.assert_called_once_with(
            "suspicious-avatars", "avatars/1/abc.jpg"
        )

    def test_delete_avatar_never_raises(self):
        fake_client = mock.MagicMock()
        fake_client.remove_object.side_effect = Exception("network down")
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ):
            delete_avatar("avatars/1/abc.jpg")  # must not raise


class PresignedAvatarUrlTest(SimpleTestCase):
    def test_returns_url_from_client(self):
        fake_client = mock.MagicMock()
        fake_client.presigned_get_object.return_value = "https://rustfs/signed"
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ):
            url = presigned_avatar_url("avatars/1/abc.jpg")
        self.assertEqual(url, "https://rustfs/signed")

    def test_returns_none_on_failure(self):
        fake_client = mock.MagicMock()
        fake_client.presigned_get_object.side_effect = Exception("boom")
        with mock.patch(
            "profiles.profiles_utils.avatar_storage.get_s3_client",
            return_value=fake_client,
        ):
            url = presigned_avatar_url("avatars/1/abc.jpg")
        self.assertIsNone(url)
