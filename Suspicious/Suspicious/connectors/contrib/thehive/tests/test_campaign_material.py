import io
import tarfile
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from common.storage import StoreError
from common.storage.fake import FakeObjectStore
from connectors.contrib.ai_model import mailtext
from connectors.contrib.ai_model.tests.test_mailtext import archive, build_tar, special

from connectors.contrib.thehive.campaign_material import (
    MAX_FILE_BYTES,
    Attachment,
    fetch_mail_material,
    select_attachments,
)

MAIL = "261007071836-7a54e9fcb2f6"
PNG_1X1 = b"\x89PNG\r\n\x1a\n" + b"\x00" * 60
BIG_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 5000


def fake_store(buckets):
    store = FakeObjectStore()
    for bucket, objects in buckets.items():
        store.ensure_bucket(bucket)
        for name, data in objects.items():
            store.put(bucket, name, io.BytesIO(data), length=len(data))
    return store


class FetchMaterialTest(SimpleTestCase):
    def test_collects_mail_parts_and_attachments(self):
        client = fake_store({
            "other-submission-261007071836": {"261007071836-aaaaaaaaaaaa/x.eml": b"X"},
            "haruto-submission-261007071836": {
                f"{MAIL}/{MAIL}.eml": b"From: a@b\r\n\r\nbody",
                f"{MAIL}/{MAIL}.headers": b"Subject: Hi\r\nFrom: a@b\r\n",
                f"{MAIL}/{MAIL}.txt": "plain https://t.example/a".encode(),
                f"{MAIL}/{MAIL}.html": b"<a href='https://h.example'>x</a>",
                f"{MAIL}/email.json": b"{}",
                f"{MAIL}/attachments/invoice.pdf": b"%PDF-1.4",
                f"{MAIL}/attachments/empty.dat": b"",
            },
        })
        m = fetch_mail_material(client, MAIL)
        self.assertIn("Subject: Hi", m.headers)
        self.assertIn("https://t.example/a", m.text)
        self.assertIn("h.example", m.html)
        self.assertEqual(m.eml, b"From: a@b\r\n\r\nbody")
        self.assertEqual(sorted(a.name for a in m.attachments), ["empty.dat", "invoice.pdf"])

    def test_unknown_mail_gives_empty_material(self):
        m = fetch_mail_material(fake_store({"a-submission-1": {}}), "999-abc")
        self.assertEqual((m.headers, m.text, m.html, m.eml, m.attachments), ("", "", "", b"", []))

    def test_the_legacy_bucket_named_after_the_submission(self):
        client = fake_store({"haruto-submission-261007071836": {f"{MAIL}/{MAIL}.headers": b"Subject: Hi"}})
        m = fetch_mail_material(client, MAIL, "haruto-submission-261007071836")
        self.assertEqual(m.headers, "Subject: Hi")

    def test_a_feeder_mail_stored_under_its_submission_prefix(self):
        client = fake_store({"feeder": {
            f"Haruto_Sato-1/{MAIL}/{MAIL}.headers": b"Subject: Hi",
            f"Haruto_Sato-1/{MAIL}/attachments/invoice.pdf": b"%PDF-1.4",
            f"Other-2/{MAIL}/{MAIL}.headers": b"not this one",
        }})
        with patch("settings.config.get_section", return_value={"feeder_bucket": "feeder"}):
            m = fetch_mail_material(client, MAIL, "Haruto_Sato-1")
        self.assertEqual(m.headers, "Subject: Hi")
        self.assertEqual([a.name for a in m.attachments], ["invoice.pdf"])

    def test_a_submission_with_no_stored_object_gives_empty_material(self):
        client = fake_store({"feeder": {"Other-2/x/x.headers": b"x"}})
        with patch("settings.config.get_section", return_value={"feeder_bucket": "feeder"}):
            m = fetch_mail_material(client, MAIL, "Haruto_Sato-1")
        self.assertEqual((m.headers, m.text, m.eml, m.attachments), ("", "", b"", []))

    def test_an_unreadable_object_logs_the_class_never_its_name(self):
        client = fake_store({"haruto-submission-261007071836": {
            f"{MAIL}/{MAIL}.headers": b"Subject: Hi",
            f"{MAIL}/attachments/secret-plan.pdf": b"%PDF",
        }})
        real_open = client.open

        def failing_open(bucket, key):
            if "secret-plan" in key:
                raise RuntimeError(f"cannot open {key}")
            return real_open(bucket, key)

        for error in (RuntimeError, None):
            with self.subTest(error=error):
                if error is None:  # a vanished object: not_found
                    client.open = lambda b, k: (_ for _ in ()).throw(StoreError("not_found", k)) \
                        if "secret-plan" in k else real_open(b, k)
                else:
                    client.open = failing_open
                with self.assertLogs("tasp.cron.update_ongoing_case_jobs", "WARNING") as logs:
                    m = fetch_mail_material(client, MAIL, "haruto-submission-261007071836")
                self.assertEqual(m.headers, "Subject: Hi")
                self.assertNotIn("secret-plan", "\n".join(logs.output))
                self.assertIn("RuntimeError" if error else "not_found", "\n".join(logs.output))

    def test_a_store_outage_propagates(self):
        client = fake_store({})
        client.list_buckets = client.bucket_exists = lambda *a: (_ for _ in ()).throw(StoreError("unavailable"))
        for bucket_name in ("", "haruto-submission-261007071836"):
            with self.subTest(bucket_name=bucket_name), self.assertRaises(StoreError):
                fetch_mail_material(client, MAIL, bucket_name)


# A web upload's tar: shutil.make_archive of the submission dir, the uploaded file included.
WEB_TAR = {
    "./": special("./", tarfile.DIRTYPE),
    "./user_submission.eml": b"From: uploaded@b\r\n\r\nraw",
    f"./{MAIL}.eml": b"From: a@b\r\n\r\nbody",
    f"./{MAIL}.headers": b"Subject: Hi\r\nFrom: a@b\r\n",
    f"./{MAIL}.txt": "plain https://t.example/a".encode(),
    f"./{MAIL}.html": b"<a href='https://h.example'>x</a>",
    "./email.json": b"{}",
    "./attachments": special("./attachments", tarfile.DIRTYPE),
    "./attachments/invoice.pdf": b"%PDF-1.4",
    "./attachments/empty.dat": b"",
}
EMPTY = ("", "", "", b"", [])


def _parts(m):
    return (m.headers, m.text, m.html, m.eml, sorted((a.name, a.data) for a in m.attachments))


class TarFallbackTest(SimpleTestCase):
    """A web upload (MailArchive.bucket_name == "") has no store location: its tar stands in."""

    def fetch(self, members, client=None):
        return fetch_mail_material(client or fake_store({}), MAIL, "", archive(build_tar(members)))

    def test_a_store_miss_reads_every_part_from_the_tar(self):
        m = self.fetch(WEB_TAR)
        self.assertEqual(_parts(m), (
            "Subject: Hi\r\nFrom: a@b\r\n", "plain https://t.example/a",
            "<a href='https://h.example'>x</a>", b"From: a@b\r\n\r\nbody",
            [("empty.dat", b""), ("invoice.pdf", b"%PDF-1.4")],
        ))

    def test_a_store_hit_does_not_read_the_tar(self):
        client = fake_store({"haruto-submission-261007071836": {f"{MAIL}/{MAIL}.headers": b"from store"}})
        m = self.fetch({f"{MAIL}.headers": b"from tar"}, client)
        self.assertEqual(m.headers, "from store")

    def test_unsafe_members_refuse_the_whole_tar(self):
        unsafe = {
            "absolute": {"/etc/passwd": b"x"},
            "dotdot": {"../evil.txt": b"x"},
            "symlink": {"link": special("link", tarfile.SYMTYPE, f"{MAIL}.txt")},
            "hardlink": {"hl": special("hl", tarfile.LNKTYPE, f"{MAIL}.txt")},
        }
        for what, extra in unsafe.items():
            with self.subTest(what), self.assertLogs("tasp.cron.update_ongoing_case_jobs", "WARNING") as logs:
                self.assertEqual(_parts(self.fetch({**WEB_TAR, **extra})), EMPTY)
            self.assertNotIn("passwd", "\n".join(logs.output))

    def test_too_many_members_or_bytes_refuse_the_tar(self):
        many = {f"f{i}": b"x" for i in range(mailtext.MAX_MEMBERS + 1)}
        self.assertEqual(_parts(self.fetch({**WEB_TAR, **many})), EMPTY)
        with patch.object(mailtext, "MAX_TOTAL_BYTES", 1024):
            self.assertEqual(_parts(self.fetch({**WEB_TAR, "pad.bin": b"\0" * 2048})), EMPTY)

    def test_garbage_or_no_tar_gives_empty_material(self):
        client = fake_store({})
        for mail_archive in (None, SimpleNamespace(archive=None), archive(b"not a tar")):
            with self.subTest(mail_archive=mail_archive):
                self.assertEqual(_parts(fetch_mail_material(client, MAIL, "", mail_archive)), EMPTY)
        self.assertEqual(_parts(fetch_mail_material(client, MAIL)), EMPTY)

    def test_each_member_read_stops_one_byte_past_the_file_cap(self):
        from connectors.contrib.thehive import campaign_material

        with patch.object(campaign_material, "MAX_FILE_BYTES", 8):
            m = self.fetch({**WEB_TAR, "./attachments/big.bin": b"B" * 100})
        big = next(a for a in m.attachments if a.name == "big.bin")
        self.assertEqual(big.data, b"B" * 9)

    def test_an_uploaded_file_stands_in_only_when_the_mail_eml_is_absent(self):
        members = {k: v for k, v in WEB_TAR.items() if k != f"./{MAIL}.eml"}
        self.assertEqual(self.fetch(members).eml, b"From: uploaded@b\r\n\r\nraw")


def _att(name, data):
    return Attachment(name=name, data=data)


class SelectAttachmentsTest(SimpleTestCase):
    def _select(self, *atts):
        kept, skipped = select_attachments(list(atts))
        return [a.name for a in kept], {n: r for n, _h, _s, r in skipped}

    def test_empty_files_are_skipped(self):
        kept, skipped = self._select(_att("empty.dat", b""), _att("f.pdf", b"%PDF"))
        self.assertEqual(kept, ["f.pdf"])
        self.assertEqual(skipped, {"empty.dat": "empty"})

    def test_tracking_pixel_sized_images_are_skipped_but_real_images_kept(self):
        kept, skipped = self._select(_att("logo.png", PNG_1X1), _att("scan.png", BIG_PNG))
        self.assertEqual(kept, ["scan.png"])
        self.assertIn("pixel", skipped["logo.png"])

    def test_duplicates_are_kept_once(self):
        kept, skipped = self._select(_att("a.pdf", b"%PDF-1"), _att("b.pdf", b"%PDF-1"))
        self.assertEqual(kept, ["a.pdf"])
        self.assertEqual(skipped, {"b.pdf": "duplicate of a.pdf"})

    def test_oversized_files_are_skipped_with_their_hash(self):
        kept, skipped = select_attachments([_att("huge.bin", b"\x01" * (MAX_FILE_BYTES + 1))])
        self.assertEqual(kept, [])
        name, sha, size, reason = skipped[0]
        self.assertEqual((name, size), ("huge.bin", MAX_FILE_BYTES + 1))
        self.assertEqual(len(sha), 64)
        self.assertIn("too large", reason)

    def test_documents_and_forms_are_kept(self):
        kept, _ = self._select(_att("notice.pdf", b"%PDF"), _att("form.html", b"<form>"))
        self.assertEqual(kept, ["notice.pdf", "form.html"])
