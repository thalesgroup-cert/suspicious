"""Web uploads share one bucket, one prefix per submission; ids stay S3-safe whatever the username."""
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from case_handler.case_utils.form_handlers.mail import mail_form

from case_handler.case_utils.form_handlers.mail.minio import MinioManager
from common.storage import FREE_FORM_BUCKET_TAGS
from common.storage.fake import FakeObjectStore
from case_handler.case_utils.form_handlers.mail.mail_form import (
    DEFAULT_WEB_BUCKET,
    MailFormHandler,
    bucket_name_for,
    web_submission_bucket,
)

MAIL_ID = "260326141159-0123456789ab"
S3_BUCKET = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")


class BucketNameForTests(SimpleTestCase):
    def test_plain_username_is_unchanged(self):
        self.assertEqual(
            bucket_name_for("theo.bhang", MAIL_ID), "theo-bhang-submission-260326141159"
        )

    def test_uppercase_and_underscore(self):
        self.assertEqual(
            bucket_name_for("Elena_Voss", MAIL_ID), "elena-voss-submission-260326141159"
        )

    def test_unicode_is_folded_to_ascii(self):
        self.assertEqual(bucket_name_for("ÉLÉNA", MAIL_ID), "elena-submission-260326141159")

    def test_seventy_character_username_is_cut_and_keeps_the_suffix(self):
        name = bucket_name_for("a" * 70, MAIL_ID)
        self.assertEqual(len(name), 63)
        self.assertTrue(name.endswith("-submission-260326141159"))

    def test_cut_never_leaves_a_dangling_or_doubled_hyphen(self):
        name = bucket_name_for("a" * 38 + "_" + "b" * 31, MAIL_ID)
        self.assertNotIn("--", name)
        self.assertTrue(S3_BUCKET.match(name), name)

    def test_nothing_usable_falls_back_to_user(self):
        for raw in ("...", "", "___", "日本語"):
            with self.subTest(raw=raw):
                self.assertEqual(
                    bucket_name_for(raw, MAIL_ID), "user-submission-260326141159"
                )

    def test_repeated_separators_collapse_and_edges_are_trimmed(self):
        self.assertEqual(
            bucket_name_for(".john..doe__x.", MAIL_ID), "john-doe-x-submission-260326141159"
        )

    def test_every_result_is_a_valid_bucket_name(self):
        for raw in ("Elena_Voss", "ÉLÉNA", "a" * 70, "...", "a.b.c", "X" * 39, "-lead", "trail-"):
            with self.subTest(raw=raw):
                self.assertRegex(bucket_name_for(raw, MAIL_ID), S3_BUCKET)

    def test_two_submissions_of_the_same_user_differ_by_suffix(self):
        self.assertNotEqual(
            bucket_name_for("Elena_Voss", "260326141159-aaaaaaaaaaaa"),
            bucket_name_for("Elena_Voss", "260326141200-bbbbbbbbbbbb"),
        )


class HandlerUsesOneSharedBucketTests(SimpleTestCase):
    def _handle(self, username="Elena_Voss@meridian.example", settings=None):
        mod = mail_form.__name__
        with tempfile.TemporaryDirectory() as tmp:
            eml = Path(tmp) / "in.eml"
            eml.write_bytes(b"From: a@example.com\r\nSubject: s\r\n\r\nbody\r\n")
            mail_file = SimpleNamespace(name="in.eml", temporary_file_path=lambda: str(eml))
            user = SimpleNamespace(username=username)
            with mock.patch(f"{mod}.MinioManager") as minio, \
                    mock.patch(f"{mod}.ProcessEmailService"), \
                    mock.patch("settings.config.get_section", return_value=settings or {}), \
                    mock.patch(f"{mod}.WebSubmissionService") as web:
                MailFormHandler(user, base_path=Path(tmp) / "case").handle(mail_file)
        return minio.return_value.upload_directory.call_args.kwargs, web

    def test_upload_goes_to_the_shared_bucket_under_a_per_submission_prefix(self):
        kwargs, web = self._handle()
        self.assertEqual(kwargs["bucket_name"], DEFAULT_WEB_BUCKET)
        self.assertRegex(kwargs["base_object_path"], r"^elena-voss-submission-\d{12}-[0-9a-f]+$")
        config = web.return_value.process_emails.call_args.args[0]
        self.assertEqual(config.user_email, "Elena_Voss@meridian.example")

    def test_the_shared_bucket_is_not_tagged_as_a_pending_submission(self):
        # A Status tag on the bucket would make the legacy scanner ingest all of it.
        kwargs, _ = self._handle()
        self.assertIs(kwargs["tag_bucket"], False)

    def test_two_submissions_never_share_a_prefix(self):
        a, _ = self._handle()
        b, _ = self._handle()
        self.assertNotEqual(a["base_object_path"], b["base_object_path"])

    def test_bucket_name_is_configurable(self):
        with mock.patch("settings.config.get_section", return_value={"web_bucket": " custom-mails "}):
            self.assertEqual(web_submission_bucket(), "custom-mails")
        with mock.patch("settings.config.get_section", return_value={}):
            self.assertEqual(web_submission_bucket(), DEFAULT_WEB_BUCKET)


class MinioManagerSharedBucketTests(SimpleTestCase):
    def _manager(self, store):
        with mock.patch.object(MinioManager, "_default_client", return_value=store), \
                mock.patch.object(MinioManager, "_presign_client", return_value=None):
            return MinioManager()

    def _store(self):
        return FakeObjectStore(capabilities={FREE_FORM_BUCKET_TAGS})

    def test_upload_directory_tags_a_new_bucket_by_default_and_not_when_shared(self):
        for tag_bucket, expected in ((True, {"Status": "To Do"}), (False, {})):
            with self.subTest(tag_bucket=tag_bucket), tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "a.eml").write_bytes(b"x")
                store = self._store()
                self._manager(store).upload_directory(
                    Path(tmp), "b", base_object_path="p", tag_bucket=tag_bucket
                )
                self.assertEqual(store.get_bucket_labels("b"), expected)

    def test_objects_land_under_the_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.eml").write_bytes(b"x")
            store = self._store()
            store.ensure_bucket("b")
            self._manager(store).upload_directory(Path(tmp), "b", base_object_path="p/", tag_bucket=False)
            self.assertEqual([o.name for o in store.list("b")], ["p/a.eml"])

    def test_losing_the_creation_race_still_counts_as_the_bucket_existing(self):
        store = self._store()
        store.ensure_bucket("b")
        manager = self._manager(store)
        with mock.patch.object(store, "bucket_exists", return_value=False):
            self.assertTrue(manager.ensure_bucket("b"))
