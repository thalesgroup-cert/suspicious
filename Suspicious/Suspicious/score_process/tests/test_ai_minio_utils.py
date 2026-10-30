import io
from unittest import mock

from django.test import SimpleTestCase

from common.storage import StoreError
from common.storage.fake import FakeObjectStore

from score_process.scoring.cortex_analyzers.contrib.ai_minio_utils import (
    MAIL_TEXT_MAX_BYTES,
    _find_mail_bucket,
    fetch_mail_files_from_minio,
    fetch_mail_text_from_minio,
)

MAIL = "261007071836-7a54e9fcb2f6"


def fake_store(buckets):
    store = FakeObjectStore()
    for bucket, objects in buckets.items():
        store.ensure_bucket(bucket)
        for name, data in objects.items():
            store.put(bucket, name, io.BytesIO(data), length=len(data))
    return store


# Four reporters whose submissions landed in the same second share the suffix.
SAME_SECOND = {
    "camila.reyes-submission-261007071836": {"261007071836-aaaaaaaaaaaa/x.eml": b"A"},
    "haruto.sato-submission-261007071836": {f"{MAIL}/mail.eml": b"B", f"{MAIL}/attachments/f.pdf": b"%PDF"},
}


class FindBucketTest(SimpleTestCase):
    def test_picks_the_bucket_that_actually_holds_the_mail(self):
        self.assertEqual(
            _find_mail_bucket(fake_store(SAME_SECOND), MAIL), "haruto.sato-submission-261007071836"
        )

    def test_returns_none_when_no_bucket_has_it(self):
        self.assertIsNone(_find_mail_bucket(fake_store({"a-submission-1": {}}), "999-abc"))


class _Failing(FakeObjectStore):
    def __init__(self, code):
        super().__init__()
        self.code = code

    def list_buckets(self):
        raise StoreError(self.code, "boom")


class OutageTest(SimpleTestCase):
    def test_not_found_is_treated_as_missing(self):
        self.assertIsNone(_find_mail_bucket(_Failing("not_found"), MAIL))
        self.assertEqual(fetch_mail_files_from_minio(_Failing("not_found"), MAIL), ("", "", "", ""))

    def test_other_errors_propagate(self):
        for code in ("unavailable", "access_denied"):
            with self.subTest(code=code):
                with self.assertRaises(StoreError):
                    _find_mail_bucket(_Failing(code), MAIL)
                with self.assertRaises(StoreError):
                    fetch_mail_files_from_minio(_Failing(code), MAIL)

    def test_listing_failure_after_bucket_found_propagates(self):
        class ListFails(FakeObjectStore):
            def list(self, bucket, prefix="", recursive=True):
                if recursive and prefix == MAIL:
                    raise StoreError("unavailable", "boom")
                return super().list(bucket, prefix, recursive)

        store = ListFails()
        store.ensure_bucket("h-submission-261007071836")
        store.put("h-submission-261007071836", f"{MAIL}/m.eml", io.BytesIO(b"x"))
        with self.assertRaises(StoreError):
            fetch_mail_files_from_minio(store, MAIL)


BUCKET = "haruto.sato-submission-261007071836"
MAIL_OBJECTS = {
    f"{MAIL}/ref.headers": b"Subject: hi\n",
    f"{MAIL}/ref.txt": b"Dear user, verify your account",
    f"{MAIL}/ref.eml": b"E" * 50,
    f"{MAIL}/ref.html": b"<p>x</p>",
    f"{MAIL}/attachments/note.txt": b"an attachment, not the mail",
    f"{MAIL}/attachments/f.pdf": b"%PDF",
}


class _Recording(FakeObjectStore):
    def __init__(self):
        super().__init__()
        self.opened = []

    def open(self, bucket, key):
        self.opened.append(key)
        return super().open(bucket, key)


def recording_store(objects=MAIL_OBJECTS):
    return recording_store_in(BUCKET, objects)


def recording_store_in(bucket, objects=MAIL_OBJECTS):
    store = _Recording()
    store.ensure_bucket(bucket)
    for name, data in objects.items():
        store.put(bucket, name, io.BytesIO(data), length=len(data))
    return store


class FetchMailTextTest(SimpleTestCase):
    def test_returns_the_headers_and_the_body_text(self):
        self.assertEqual(
            fetch_mail_text_from_minio(recording_store(), MAIL),
            ("Subject: hi\n", "Dear user, verify your account"),
        )

    def test_opens_only_the_top_level_txt_and_headers_objects(self):
        store = recording_store()
        fetch_mail_text_from_minio(store, MAIL)
        self.assertEqual(sorted(store.opened), [f"{MAIL}/ref.headers", f"{MAIL}/ref.txt"])

    def test_no_bucket_or_no_such_objects_give_empty_strings(self):
        self.assertEqual(fetch_mail_text_from_minio(fake_store({"a-submission-1": {}}), MAIL), ("", ""))
        only_eml = recording_store({f"{MAIL}/ref.eml": b"E"})
        self.assertEqual(fetch_mail_text_from_minio(only_eml, MAIL), ("", ""))
        self.assertEqual(only_eml.opened, [])

    def test_each_read_is_capped(self):
        objects = {f"{MAIL}/ref.headers": b"H" * 50, f"{MAIL}/ref.txt": b"T" * 50}
        headers, txt = fetch_mail_text_from_minio(recording_store(objects), MAIL, max_bytes=10)
        self.assertEqual((headers, txt), ("H" * 10, "T" * 10))

    def test_the_default_cap_is_the_named_constant(self):
        objects = {f"{MAIL}/ref.headers": b"H", f"{MAIL}/ref.txt": b"T" * (MAIL_TEXT_MAX_BYTES + 100)}
        _, txt = fetch_mail_text_from_minio(recording_store(objects), MAIL)
        self.assertEqual(len(txt), MAIL_TEXT_MAX_BYTES)

    def test_a_cut_inside_a_character_is_replaced_not_fatal(self):
        objects = {f"{MAIL}/ref.headers": b"H", f"{MAIL}/ref.txt": "caf\u00e9".encode()}
        _, txt = fetch_mail_text_from_minio(recording_store(objects), MAIL, max_bytes=4)
        self.assertEqual(txt, "caf\ufffd")

    def test_not_found_is_treated_as_missing_and_other_errors_propagate(self):
        self.assertEqual(fetch_mail_text_from_minio(_Failing("not_found"), MAIL), ("", ""))
        for code in ("unavailable", "access_denied"):
            with self.subTest(code=code):
                with self.assertRaises(StoreError):
                    fetch_mail_text_from_minio(_Failing(code), MAIL)

    def test_an_object_that_vanishes_after_the_listing_is_treated_as_missing(self):
        class Vanishing(_Recording):
            def open(self, bucket, key):
                raise StoreError("not_found", "gone")

        store = Vanishing()
        store.ensure_bucket(BUCKET)
        store.put(BUCKET, f"{MAIL}/ref.txt", io.BytesIO(b"x"))
        self.assertEqual(fetch_mail_text_from_minio(store, MAIL), ("", ""))


FEEDER = "suspicious-feeder"
SUB = "sub-1"
FEEDER_CONFIG = {"feeder_bucket": FEEDER}


def feeder_store(objects):
    store = _Recording()
    store.ensure_bucket(FEEDER)
    for name, data in objects.items():
        store.put(FEEDER, name, io.BytesIO(data), length=len(data))
    return store


PREFIX_OBJECTS = {
    f"{SUB}/{MAIL}/ref.headers": b"Subject: prefix\n",
    f"{SUB}/{MAIL}/ref.txt": b"Text from the prefix layout",
    f"{SUB}/{MAIL}/ref.eml": b"E" * 50,
    f"{SUB}/{MAIL}/attachments/note.txt": b"an attachment, not the mail",
    f"{SUB}/reporter-submission.eml": b"wrapper",
    f"sub-2/{MAIL}/ref.txt": b"another submission",
}


@mock.patch("settings.config.get_section", return_value=FEEDER_CONFIG)
class FetchMailTextLayoutsTest(SimpleTestCase):
    def test_the_feeder_prefix_layout_is_found_from_the_submission_id(self, _config):
        store = feeder_store(PREFIX_OBJECTS)
        self.assertEqual(
            fetch_mail_text_from_minio(store, MAIL, bucket_name=SUB),
            ("Subject: prefix\n", "Text from the prefix layout"),
        )
        self.assertEqual(
            sorted(store.opened), [f"{SUB}/{MAIL}/ref.headers", f"{SUB}/{MAIL}/ref.txt"]
        )

    def test_a_submission_id_s3_cannot_name_a_bucket_after_is_found_in_the_feeder_bucket(self, _config):
        sub = "John.Doe-submission-261007071836"  # the feeder keeps the reporter's case in the id
        store = feeder_store({f"{sub}/{MAIL}/ref.headers": b"Subject: hi\n", f"{sub}/{MAIL}/ref.txt": b"Body"})
        real_bucket_exists = store.bucket_exists

        def bucket_exists(bucket):  # S3 answers 400 to a bucket name it cannot hold, mapped to invalid
            if bucket != bucket.lower():
                raise StoreError("invalid", "400 Bad Request", bucket=bucket)
            return real_bucket_exists(bucket)

        store.bucket_exists = bucket_exists
        self.assertEqual(fetch_mail_text_from_minio(store, MAIL, bucket_name=sub), ("Subject: hi\n", "Body"))
        self.assertEqual(sorted(store.opened), [f"{sub}/{MAIL}/ref.headers", f"{sub}/{MAIL}/ref.txt"])

    def test_a_bucket_named_like_the_submission_is_used_even_without_the_timestamp_suffix(self, _config):
        store = recording_store_in("case-bucket")
        self.assertEqual(
            fetch_mail_text_from_minio(store, MAIL, bucket_name="case-bucket"),
            ("Subject: hi\n", "Dear user, verify your account"),
        )
        self.assertEqual(sorted(store.opened), [f"{MAIL}/ref.headers", f"{MAIL}/ref.txt"])

    def test_nothing_under_the_submission_falls_back_to_the_suffix_search(self, _config):
        store = recording_store()  # legacy bucket named <reporter>-submission-<timestamp>
        store.ensure_bucket(FEEDER)
        store.ensure_bucket("unrelated")
        for name in ("sub-9", "unrelated"):  # not a bucket with the mail / no such prefix in feeder
            with self.subTest(bucket_name=name):
                self.assertEqual(
                    fetch_mail_text_from_minio(store, MAIL, bucket_name=name),
                    ("Subject: hi\n", "Dear user, verify your account"),
                )

    def test_an_empty_bucket_name_goes_straight_to_the_suffix_search(self, _config):
        self.assertEqual(
            fetch_mail_text_from_minio(recording_store(), MAIL, bucket_name=""),
            ("Subject: hi\n", "Dear user, verify your account"),
        )

    def test_without_a_feeder_bucket_only_a_real_bucket_or_the_suffix_search_applies(self, config):
        config.return_value = {}
        self.assertEqual(
            fetch_mail_text_from_minio(recording_store(), MAIL, bucket_name=SUB),
            ("Subject: hi\n", "Dear user, verify your account"),
        )

    def test_a_missing_feeder_bucket_is_not_found_not_an_error(self, _config):
        self.assertEqual(fetch_mail_text_from_minio(FakeObjectStore(), MAIL, bucket_name=SUB), ("", ""))

    def test_a_store_error_while_resolving_the_submission_propagates(self, _config):
        class Down(_Recording):
            def bucket_exists(self, bucket):
                raise StoreError("unavailable", "boom")

        with self.assertRaises(StoreError):
            fetch_mail_text_from_minio(Down(), MAIL, bucket_name=SUB)
