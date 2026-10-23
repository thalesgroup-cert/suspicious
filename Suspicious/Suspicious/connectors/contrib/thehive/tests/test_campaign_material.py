import io

from django.test import SimpleTestCase

from common.storage.fake import FakeObjectStore

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
