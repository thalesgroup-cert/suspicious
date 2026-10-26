from unittest import mock

from django.test import SimpleTestCase

from common.storage import StoreError
from common.storage.fake import FakeObjectStore
from mail_feeder.utils.email_preview.eml2png_renderer import Eml2PngRenderer

PATCH = "mail_feeder.utils.email_preview.eml2png_renderer.get_store"


class SavePreviewTest(SimpleTestCase):
    def test_puts_png_and_stamps_mail(self):
        store, mail = FakeObjectStore(), mock.Mock(pk=7)
        with mock.patch(PATCH, return_value=store):
            Eml2PngRenderer().save_preview_to_mail(mail, b"png")
        with store.open("mail-previews", "7.png") as s:
            self.assertEqual(s.read(), b"png")
        self.assertEqual(mail.preview_object_key, "7.png")

    def test_continues_when_ensure_bucket_fails(self):
        store = FakeObjectStore()
        store.ensure_bucket("mail-previews")
        store.ensure_bucket = mock.Mock(side_effect=StoreError("access_denied"))
        mail = mock.Mock(pk=8)
        with mock.patch(PATCH, return_value=store):
            Eml2PngRenderer().save_preview_to_mail(mail, b"png")
        self.assertEqual(mail.preview_object_key, "8.png")

    def test_unconfigured_store_skips(self):
        mail = mock.Mock(pk=9)
        with mock.patch(PATCH, side_effect=RuntimeError("no config")):
            Eml2PngRenderer().save_preview_to_mail(mail, b"png")
        mail.save.assert_not_called()
