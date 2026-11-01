from django.contrib import admin
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import RequestFactory, TestCase

from ai_model.models import LabelRecord, LabelSyncState
from case_handler.models import Case


def make(**kw):
    base = dict(
        message_id="a@b", message_id_hash="h", source="imap_folder", label="1_SPAM",
        label_class="Unwanted", trust="folder",
    )
    return LabelRecord.objects.create(**{**base, **kw})


class LabelRecordTest(TestCase):
    def test_trainable(self):
        self.assertTrue(make().trainable)
        self.assertFalse(make(status="flagged").trainable)
        self.assertFalse(make(status="superseded").trainable)
        self.assertFalse(make(trust="proposal").trainable)
        self.assertFalse(make(trust="verdict").trainable)

    def test_null_case_and_set_null(self):
        user = get_user_model().objects.create_user(username="u", password="p")
        case = Case.objects.create(description="", reporter=user)
        rec = make(case=case)
        case.delete()
        rec.refresh_from_db()
        self.assertIsNone(rec.case)
        self.assertIsNone(make().case)

    def test_sync_state_unique_folder(self):
        LabelSyncState.objects.create(folder="1_SPAM", uidvalidity=1, last_uid=0)
        with self.assertRaises(IntegrityError), transaction.atomic():
            LabelSyncState.objects.create(folder="1_SPAM", uidvalidity=2, last_uid=5)
        self.assertEqual(LabelSyncState.objects.get().skipped, 0)

    def test_indexes(self):
        fields = [tuple(i.fields) for i in LabelRecord._meta.indexes]
        self.assertIn(("message_id_hash", "source", "status"), fields)
        self.assertIn(("trust", "status"), fields)

    def test_admin_read_only(self):
        user = get_user_model().objects.create_superuser("s", "s@x.y", "p")
        req = RequestFactory().get("/")
        req.user = user
        for model in (LabelRecord, LabelSyncState):
            ma = admin.site._registry[model]
            self.assertFalse(ma.has_add_permission(req))
            self.assertFalse(ma.has_change_permission(req))
            self.assertFalse(ma.has_delete_permission(req))
