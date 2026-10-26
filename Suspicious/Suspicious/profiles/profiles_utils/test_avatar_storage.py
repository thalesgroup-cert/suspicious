import io
from unittest import mock

from django.test import SimpleTestCase
from PIL import Image

from common.storage import FakeObjectStore, StoreError

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


BUCKET = "suspicious-avatars"
_GET = "profiles.profiles_utils.avatar_storage.get_store"
_PRESIGN = "profiles.profiles_utils.avatar_storage.get_presign_store"


class StoreAvatarTest(SimpleTestCase):
    def test_store_avatar_uploads_and_returns_key(self):
        store = FakeObjectStore()
        with mock.patch(_GET, return_value=store):
            key = store_avatar(42, b"jpegbytes")
        self.assertTrue(key.startswith("avatars/42/"))
        self.assertTrue(key.endswith(".jpg"))
        with store.open(BUCKET, key) as s:
            self.assertEqual(s.read(), b"jpegbytes")

    def test_store_avatar_creates_bucket_if_missing(self):
        store = FakeObjectStore()
        with mock.patch(_GET, return_value=store):
            store_avatar(1, b"bytes")
        self.assertTrue(store.bucket_exists(BUCKET))

    def test_store_avatar_uses_configured_bucket_name(self):
        store = FakeObjectStore()
        with mock.patch(_GET, return_value=store), mock.patch(
            "profiles.profiles_utils.avatar_storage.get_section",
            return_value={"avatars_bucket": "custom-bucket"},
        ):
            key = store_avatar(42, b"jpegbytes")
        self.assertTrue(store.bucket_exists("custom-bucket"))
        self.assertFalse(store.bucket_exists(BUCKET))
        self.assertEqual(store.stat("custom-bucket", key).size, 9)


class DeleteAvatarTest(SimpleTestCase):
    def test_delete_avatar_removes_object(self):
        store = FakeObjectStore()
        with mock.patch(_GET, return_value=store):
            key = store_avatar(1, b"x")
            delete_avatar(key)
        with self.assertRaises(StoreError) as ctx:
            store.stat(BUCKET, key)
        self.assertEqual(ctx.exception.code, "not_found")

    def test_delete_avatar_never_raises(self):
        store = mock.MagicMock()
        store.delete.side_effect = StoreError("unavailable")
        with mock.patch(_GET, return_value=store):
            delete_avatar("avatars/1/abc.jpg")  # must not raise


class PresignedAvatarUrlTest(SimpleTestCase):
    def test_returns_url_from_presign_store(self):
        store = FakeObjectStore()
        with mock.patch(_PRESIGN, return_value=store):
            url = presigned_avatar_url("avatars/1/abc.jpg")
        self.assertEqual(url, f"fake://{BUCKET}/avatars/1/abc.jpg?expires=3600")

    def test_returns_none_on_failure(self):
        store = mock.MagicMock()
        store.presign_get.side_effect = StoreError("unavailable")
        with mock.patch(_PRESIGN, return_value=store):
            url = presigned_avatar_url("avatars/1/abc.jpg")
        self.assertIsNone(url)
