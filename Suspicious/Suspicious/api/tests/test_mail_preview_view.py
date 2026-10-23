"""MailPreviewView streams the cached preview PNG through the ObjectStore
registry and answers 404 when the store or the object is unavailable."""
import io
from unittest.mock import patch

from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case
from common.storage import FakeObjectStore

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


@override_settings(ROOT_URLCONF="suspicious.urls")
class MailPreviewStoreTest(TestCase):
    def setUp(self):
        user = User.objects.create_user(username="u", password="pw-12345")
        user.groups.add(Group.objects.get_or_create(name="CERT")[0])
        self.client = APIClient()
        self.client.force_authenticate(user)
        self.case = Case.objects.create(description="d", reporter=user)
        mail = type("M", (), {"pk": 1, "preview_bucket": "prev", "preview_object_key": "a.png"})()
        patcher = patch("api.views.mail_preview.MailPreviewView._get_mail", return_value=mail)
        patcher.start()
        self.addCleanup(patcher.stop)
        enq = patch("api.views.mail_preview.enqueue_preview_render")
        enq.start()
        self.addCleanup(enq.stop)

    def _get(self):
        return self.client.get(f"/api/cases/{self.case.id}/mail-preview.png")

    @patch("api.views.mail_preview.get_store")
    def test_streams_preview_from_store(self, get_store):
        store = get_store.return_value = FakeObjectStore()
        store.ensure_bucket("prev")
        store.put("prev", "a.png", io.BytesIO(PNG))
        resp = self._get()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "image/png")
        self.assertEqual(b"".join(resp.streaming_content), PNG)

    @patch("api.views.mail_preview.get_store")
    def test_404_when_object_missing(self, get_store):
        store = get_store.return_value = FakeObjectStore()
        store.ensure_bucket("prev")
        self.assertEqual(self._get().status_code, 404)

    @patch("api.views.mail_preview.get_store", side_effect=RuntimeError("no config"))
    def test_404_when_store_unavailable(self, _get_store):
        self.assertEqual(self._get().status_code, 404)
