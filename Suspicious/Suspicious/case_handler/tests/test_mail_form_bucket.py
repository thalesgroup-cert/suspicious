"""Submission bucket names must be valid S3 bucket names whatever the username."""
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from case_handler.case_utils.form_handlers.mail import mail_form
from case_handler.case_utils.form_handlers.mail.mail_form import (
    MailFormHandler,
    bucket_name_for,
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


class HandlerUsesNormalisedBucketTests(SimpleTestCase):
    def test_upload_targets_the_normalised_bucket_and_user_is_untouched(self):
        mod = mail_form.__name__
        with tempfile.TemporaryDirectory() as tmp:
            eml = Path(tmp) / "in.eml"
            eml.write_bytes(b"From: a@example.com\r\nSubject: s\r\n\r\nbody\r\n")
            mail_file = SimpleNamespace(name="in.eml", temporary_file_path=lambda: str(eml))
            user = SimpleNamespace(username="Elena_Voss@meridian.example")
            with mock.patch(f"{mod}.MinioManager") as minio, \
                    mock.patch(f"{mod}.ProcessEmailService"), \
                    mock.patch(f"{mod}.WebSubmissionService") as web:
                MailFormHandler(user, base_path=Path(tmp) / "case").handle(mail_file)

        bucket = minio.return_value.upload_directory.call_args.kwargs["bucket_name"]
        self.assertRegex(bucket, r"^elena-voss-submission-\d{12}$")
        config = web.return_value.process_emails.call_args.args[0]
        self.assertEqual(config.user_email, "Elena_Voss@meridian.example")
