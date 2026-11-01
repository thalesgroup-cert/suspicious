import io
import os
import tarfile
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail
from common.storage import FakeObjectStore, StoreError
from connectors.contrib.ai_model import mailtext
from connectors.contrib.ai_model.mailtext import read_archive_body
from connectors.providers import ProviderUnavailable
from file_process.models import File
from hash_process.models import Hash
from mail_feeder.models import Mail, MailArchive
from suspicious.storage_backends import MinioMediaStorage


def build_tar(members, mode="w:gz"):
    """members: name -> bytes, or name -> TarInfo (empty payload) for special entries."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as tar:
        for name, data in members.items():
            if isinstance(data, tarfile.TarInfo):
                tar.addfile(data)
                continue
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def archive(data: bytes):
    """What a MailArchive looks like to read_archive_body: archive.file_path opens to bytes."""
    return SimpleNamespace(archive=SimpleNamespace(file_path=ContentFile(data, name="mail.tar.gz")))


def special(name, kind, linkname=""):
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, linkname
    return info


GOOD = {"m1.txt": b"Dear user, verify your account", "m1.headers": b"Subject: hi\n", "m1.html": b"<p>x</p>"}


class ReadArchiveBodyTest(SimpleTestCase):
    def test_returns_the_txt_member_decoded(self):
        self.assertEqual(read_archive_body(archive(build_tar(GOOD))), "Dear user, verify your account")

    def test_a_plain_uncompressed_tar_and_a_dot_slash_prefix_work(self):
        members = {"./m1.txt": b"hello", "./m1.headers": b"H: v\n"}
        self.assertEqual(read_archive_body(archive(build_tar(members, "w"))), "hello")

    def test_a_directory_entry_is_allowed(self):
        members = {"./": special("./", tarfile.DIRTYPE), **GOOD}
        self.assertEqual(read_archive_body(archive(build_tar(members))), GOOD["m1.txt"].decode())

    def test_invalid_utf8_is_replaced_not_fatal(self):
        members = {"m1.txt": b"caf\xe9 offer", "m1.headers": b"H: v\n"}
        self.assertEqual(read_archive_body(archive(build_tar(members))), "caf� offer")

    def test_no_headers_member_gives_none(self):
        self.assertIsNone(read_archive_body(archive(build_tar({"m1.txt": b"body"}))))

    def test_no_txt_member_gives_none(self):
        self.assertIsNone(read_archive_body(archive(build_tar({"m1.headers": b"H: v\n"}))))

    def test_a_blank_body_gives_none(self):
        members = {"m1.txt": b" \n\t  ", "m1.headers": b"H: v\n"}
        self.assertIsNone(read_archive_body(archive(build_tar(members))))

    def test_nested_members_are_not_the_mail_body(self):
        # The Cortex analyzer reads the extraction root only: mirror that.
        members = {"sub/m1.txt": b"body", "sub/m1.headers": b"H: v\n"}
        self.assertIsNone(read_archive_body(archive(build_tar(members))))

    def test_path_escapes_are_rejected(self):
        for name in ("../evil.txt", "a/../../evil.txt", "/etc/evil.txt"):
            with self.subTest(name=name):
                self.assertIsNone(read_archive_body(archive(build_tar({**GOOD, name: b"x"}))))

    def test_a_refused_archive_logs_the_class_not_the_member_name(self):
        with self.assertLogs("connectors.contrib.ai_model", "WARNING") as logs:
            self.assertIsNone(read_archive_body(archive(build_tar({**GOOD, "../evil-name.txt": b"x"}))))
        self.assertIn("ValueError", logs.output[0])
        self.assertNotIn("evil-name", "\n".join(logs.output))

    def test_links_and_devices_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                members = {**GOOD, "link": special("link", kind, "m1.txt")}
                self.assertIsNone(read_archive_body(archive(build_tar(members))))

    def test_too_many_members_are_rejected(self):
        members = {f"f{i}": b"x" for i in range(mailtext.MAX_MEMBERS + 1)}
        self.assertIsNone(read_archive_body(archive(build_tar({**GOOD, **members}))))
        members = {f"f{i}": b"x" for i in range(mailtext.MAX_MEMBERS - len(GOOD))}
        self.assertEqual(
            read_archive_body(archive(build_tar({**GOOD, **members}))), GOOD["m1.txt"].decode()
        )

    def test_too_much_uncompressed_data_is_rejected(self):
        members = {**GOOD, "pad.bin": b"\0" * 2048}
        original = mailtext.MAX_TOTAL_BYTES
        mailtext.MAX_TOTAL_BYTES = 1024
        self.addCleanup(setattr, mailtext, "MAX_TOTAL_BYTES", original)
        self.assertIsNone(read_archive_body(archive(build_tar(members))))

    def test_a_txt_over_the_cap_is_cut_at_the_cap(self):
        original = mailtext.MAIL_TEXT_MAX_BYTES
        mailtext.MAIL_TEXT_MAX_BYTES = 1024
        self.addCleanup(setattr, mailtext, "MAIL_TEXT_MAX_BYTES", original)
        members = {"m1.txt": b"A" * 4096, "m1.headers": b"H: v\n"}
        self.assertEqual(read_archive_body(archive(build_tar(members))), "A" * 1024)

    def test_garbage_and_missing_archives_give_none(self):
        self.assertIsNone(read_archive_body(archive(b"this is not a tar file")))
        self.assertIsNone(read_archive_body(SimpleNamespace(archive=None)))
        self.assertIsNone(read_archive_body(None))


class ArchiveLocationTest(SimpleTestCase):
    """Where the bytes come from: the shared disk path first, the storage backend second."""

    def stored(self, tmp_path, file_path):
        return SimpleNamespace(archive=SimpleNamespace(tmp_path=tmp_path, file_path=file_path))

    def test_a_submitted_mail_is_read_from_tmp_path_not_from_storage(self):
        # Production shape: file_path is just the file's name, nothing is stored under it.
        broken_storage = mock.Mock()
        broken_storage.open.side_effect = FileNotFoundError("no such object")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "mail.tar.gz")
            with open(path, "wb") as handle:
                handle.write(build_tar(GOOD))
            body = read_archive_body(self.stored(path, broken_storage))
        self.assertEqual(body, GOOD["m1.txt"].decode())
        broken_storage.open.assert_not_called()

    def test_a_missing_or_relative_tmp_path_falls_back_to_storage(self):
        data = build_tar(GOOD)
        for tmp_path in ("", "/no/such/dir/mail.tar.gz", "mail.tar.gz"):
            with self.subTest(tmp_path=tmp_path):
                body = read_archive_body(self.stored(tmp_path, ContentFile(data, name="mail.tar.gz")))
                self.assertEqual(body, GOOD["m1.txt"].decode())

    def test_neither_location_readable_gives_none(self):
        broken_storage = mock.Mock()
        broken_storage.open.side_effect = FileNotFoundError("no such object")
        self.assertIsNone(read_archive_body(self.stored("/no/such/mail.tar.gz", broken_storage)))

    def test_a_file_from_the_s3_backend_is_seekable_enough_for_tarfile(self):
        class Store:  # the object-store client MinioMediaStorage wraps
            def open(self, bucket, name):
                return io.BytesIO(build_tar(GOOD))

        storage = MinioMediaStorage(client=Store(), bucket="media")
        self.assertEqual(
            read_archive_body(self.stored("", storage.open("mail.tar.gz"))), GOOD["m1.txt"].decode()
        )


MAIL = "261007071836-7a54e9fcb2f6"
BUCKET = "haruto.sato-submission-261007071836"
STORE_OBJECTS = {f"{MAIL}/ref.txt": b"Text from the store", f"{MAIL}/ref.headers": b"Subject: hi\n"}


def fake_store(objects=STORE_OBJECTS):
    store = FakeObjectStore()
    store.ensure_bucket(BUCKET)
    for name, data in objects.items():
        store.put(BUCKET, name, io.BytesIO(data), length=len(data))
    return store


class FailingStore(FakeObjectStore):
    def __init__(self, error):
        super().__init__()
        self.error = error

    def list_buckets(self):
        raise self.error


def mail_archive(tmp_path="/no/such/dir/mail.tar.gz", file_path=None):
    """A MailArchive as the connector hands it over: the mail (for the store) and the archive file."""
    if file_path is None:
        file_path = mock.Mock()
        file_path.open.side_effect = FileNotFoundError("no such object")
    return SimpleNamespace(
        mail=SimpleNamespace(mail_id=MAIL),
        archive=SimpleNamespace(tmp_path=tmp_path, file_path=file_path),
    )


class ObjectStoreFirstTest(SimpleTestCase):
    """The work dir is wiped soon after a submission: the object store is the durable copy."""

    def read(self, store, archive=None):
        with mock.patch.object(mailtext, "get_store", return_value=store):
            return read_archive_body(archive or mail_archive())

    def tar_on_disk(self, directory, members=GOOD):
        path = os.path.join(directory, "mail.tar.gz")
        with open(path, "wb") as handle:
            handle.write(build_tar(members))
        return path

    def test_the_text_comes_from_the_store_when_the_archive_is_gone_from_disk(self):
        self.assertEqual(self.read(fake_store()), "Text from the store")

    def test_the_store_wins_over_a_readable_tar(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = mail_archive(self.tar_on_disk(directory))
            self.assertEqual(self.read(fake_store(), archive), "Text from the store")

    def test_nothing_in_the_store_and_no_tar_gives_none(self):
        self.assertIsNone(self.read(fake_store({})))
        self.assertIsNone(self.read(FakeObjectStore()))

    def test_a_blank_text_in_the_store_gives_none(self):
        blank = {f"{MAIL}/ref.txt": b" \n ", f"{MAIL}/ref.headers": b"Subject: hi\n"}
        self.assertIsNone(self.read(fake_store(blank)))

    def test_a_store_without_headers_does_not_count(self):
        self.assertIsNone(self.read(fake_store({f"{MAIL}/ref.txt": b"Text from the store"})))

    def test_not_found_in_the_store_falls_back_to_a_readable_tar(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = mail_archive(self.tar_on_disk(directory))
            for store in (FakeObjectStore(), FailingStore(StoreError("not_found", "no such bucket"))):
                with self.subTest(store=type(store).__name__):
                    self.assertEqual(self.read(store, archive), GOOD["m1.txt"].decode())

    def test_a_store_error_falls_back_to_a_readable_tar(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = mail_archive(self.tar_on_disk(directory))
            store = FailingStore(StoreError("unavailable", "http://rustfs:9000 refused"))
            self.assertEqual(self.read(store, archive), GOOD["m1.txt"].decode())

    def test_a_store_error_with_no_tar_is_a_retryable_unavailable_without_detail(self):
        errors = (
            StoreError("unavailable", "could not connect to http://rustfs:9000 key=AKIA123"),
            ConnectionError("rustfs:9000 refused"),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(ProviderUnavailable) as caught:
                    self.read(FailingStore(error))
                self.assertTrue(caught.exception.retryable)
                label = error.code if isinstance(error, StoreError) else type(error).__name__
                self.assertEqual(str(caught.exception), f"object store unavailable: {label}")
                for secret in ("rustfs", "9000", "AKIA123", "http"):
                    self.assertNotIn(secret, str(caught.exception))

    def test_the_label_is_the_store_error_code_or_the_class_name(self):
        for error, label in (
            (StoreError("access_denied", "key AKIA123 refused by http://rustfs:9000"), "access_denied"),
            (StoreError("invalid", "bad request"), "invalid"),
            (RuntimeError("config: http://rustfs:9000"), "RuntimeError"),
        ):
            with self.subTest(label=label):
                with self.assertRaises(ProviderUnavailable) as caught:
                    self.read(FailingStore(error))
                self.assertEqual(str(caught.exception), f"object store unavailable: {label}")

    def test_a_denied_or_invalid_store_request_fails_at_once(self):
        for code in ("access_denied", "invalid"):
            with self.subTest(code=code):
                with self.assertRaises(ProviderUnavailable) as caught:
                    self.read(FailingStore(StoreError(code, "boom")))
                self.assertFalse(caught.exception.retryable)

    def test_the_warning_for_a_store_error_names_the_mail_and_the_label_not_the_message(self):
        error = StoreError("unavailable", "could not connect to http://rustfs:9000/bucket/key.txt")
        with self.assertLogs("connectors.contrib.ai_model", level="WARNING") as logs:
            with self.assertRaises(ProviderUnavailable):
                self.read(FailingStore(error))
        line = next(line for line in logs.output if MAIL in line)
        self.assertIn("unavailable", line)
        for detail in ("rustfs", "9000", "key.txt", "http"):
            self.assertNotIn(detail, line)

    def test_the_feeder_prefix_layout_is_found_from_the_archive_bucket_name(self):
        objects = {
            f"sub-1/{MAIL}/ref.txt": b"Text from the prefix layout",
            f"sub-1/{MAIL}/ref.headers": b"Subject: hi\n",
            f"sub-1/{MAIL}/ref.eml": b"E" * 50,
            f"sub-1/{MAIL}/attachments/note.txt": b"an attachment",
        }
        store = FakeObjectStore()
        store.ensure_bucket("suspicious-feeder")
        for name, data in objects.items():
            store.put("suspicious-feeder", name, io.BytesIO(data), length=len(data))
        opened = []
        real_open = store.open
        store.open = lambda bucket, key: (opened.append(key), real_open(bucket, key))[1]
        archive = mail_archive()
        archive.bucket_name = "sub-1"
        with mock.patch("settings.config.get_section", return_value={"feeder_bucket": "suspicious-feeder"}):
            self.assertEqual(self.read(store, archive), "Text from the prefix layout")
        self.assertEqual(sorted(opened), [f"sub-1/{MAIL}/ref.headers", f"sub-1/{MAIL}/ref.txt"])

    def test_a_store_error_and_a_tar_without_text_is_still_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = mail_archive(self.tar_on_disk(directory, {"m1.headers": b"H: v\n"}))
            with self.assertRaises(ProviderUnavailable):
                self.read(FailingStore(StoreError("unavailable", "boom")), archive)

    def test_without_a_mail_id_the_store_is_not_consulted(self):
        store = mock.Mock()
        with mock.patch.object(mailtext, "get_store", return_value=store) as get_store:
            self.assertIsNone(read_archive_body(archive(build_tar({"m1.headers": b"H: v\n"}))))
        get_store.assert_not_called()


class ReadArchiveMaterialTest(SimpleTestCase):
    """The headers and the text, the same bytes the Cortex analyzer read, from the same sources."""

    def read(self, store, archive=None):
        with mock.patch.object(mailtext, "get_store", return_value=store):
            return mailtext.read_archive_material(archive or mail_archive())

    def test_material_from_the_store_by_the_mail_id_bucket(self):
        self.assertEqual(
            self.read(fake_store()), mailtext.MailMaterial(headers="Subject: hi\n", text="Text from the store")
        )

    def test_material_from_the_store_in_the_feeder_prefix_layout(self):
        store = FakeObjectStore()
        store.ensure_bucket("suspicious-feeder")
        for name, data in ((f"sub-1/{MAIL}/ref.txt", b"Prefixed text"), (f"sub-1/{MAIL}/ref.headers", b"From: a\n")):
            store.put("suspicious-feeder", name, io.BytesIO(data), length=len(data))
        archive = mail_archive()
        archive.bucket_name = "sub-1"
        with mock.patch("settings.config.get_section", return_value={"feeder_bucket": "suspicious-feeder"}):
            material = self.read(store, archive)
        self.assertEqual(material, mailtext.MailMaterial(headers="From: a\n", text="Prefixed text"))

    def test_a_web_upload_with_nothing_in_the_store_is_read_from_its_tar(self):
        # A web-uploaded mail has no submission bucket and no copy in the store: the tar is all there is.
        store = fake_store({"261007071836-0000000000aa/ref.txt": b"another mail"})
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "mail.tar.gz")
            with open(path, "wb") as handle:
                handle.write(build_tar(GOOD))
            archive = mail_archive(path)
            archive.bucket_name = ""
            material = self.read(store, archive)
        self.assertEqual(material, mailtext.MailMaterial(headers="Subject: hi\n", text=GOOD["m1.txt"].decode()))

    def test_tar_headers_are_capped_and_decoded_like_the_text(self):
        original = mailtext.MAIL_TEXT_MAX_BYTES
        mailtext.MAIL_TEXT_MAX_BYTES = 1024
        self.addCleanup(setattr, mailtext, "MAIL_TEXT_MAX_BYTES", original)
        members = {"m1.txt": b"body", "m1.headers": b"X-Pad: caf\xe9" + b"A" * 4096}  # 11 bytes + padding
        material = mailtext.read_archive_material(archive(build_tar(members)))
        self.assertEqual(material.headers, "X-Pad: caf�" + "A" * (1024 - 11))

    def test_a_tar_without_a_headers_member_gives_none(self):
        self.assertIsNone(mailtext.read_archive_material(archive(build_tar({"m1.txt": b"body"}))))

    def test_a_tar_with_blank_headers_gives_none(self):
        members = {"m1.txt": b"body", "m1.headers": b" \n\n"}
        self.assertIsNone(mailtext.read_archive_material(archive(build_tar(members))))

    def test_a_store_outage_with_no_tar_is_unavailable(self):
        with self.assertRaises(ProviderUnavailable) as caught:
            self.read(FailingStore(StoreError("unavailable", "http://rustfs:9000 refused")))
        self.assertTrue(caught.exception.retryable)
        self.assertEqual(str(caught.exception), "object store unavailable: unavailable")

    def test_read_archive_body_returns_only_the_text(self):
        self.assertEqual(read_archive_body(archive(build_tar(GOOD))), GOOD["m1.txt"].decode())
        with mock.patch.object(mailtext, "get_store", return_value=fake_store()):
            self.assertEqual(read_archive_body(mail_archive()), "Text from the store")


class HeaderDictTest(SimpleTestCase):
    """Keyed as the Cortex analyzer built it (mail_archive.get_header_dict_list), MIME words decoded."""

    def test_a_mime_encoded_subject_is_decoded(self):
        headers = mailtext.header_dict("Subject: =?utf-8?B?RmFjdHVyZSBpbXBhecOpZQ==?=\nFrom: a@b.example")
        self.assertEqual(headers, {"Subject": ["Facture impayée"], "From": ["a@b.example"]})

    def test_repeated_keys_keep_every_value_in_order(self):
        headers = mailtext.header_dict("Received: from a\nReceived: from b\nSubject: hi\n")
        self.assertEqual(headers, {"Received": ["from a", "from b"], "Subject": ["hi"]})

    def test_no_headers_gives_an_empty_dict(self):
        self.assertEqual(mailtext.header_dict(""), {})

    def test_crlf_and_cr_line_ends_read_as_the_cortex_analyzer_read_them(self):
        # The analyzer opened the .headers file in text mode: every line end became "\n".
        expected = mailtext.header_dict("Subject: a\n b\nFrom: x@y.example\n")
        self.assertEqual(mailtext.header_dict("Subject: a\r\n b\r\nFrom: x@y.example\r\n"), expected)
        self.assertEqual(mailtext.header_dict("Subject: a\r b\rFrom: x@y.example\r"), expected)

    def test_quotes_a_backslash_and_a_replacement_character_survive_the_round_trip(self):
        value = "It's \"urgent\" C:\\pay \ufffd now"
        self.assertEqual(mailtext.header_dict(f"Subject: {value}\n"), {"Subject": [value]})


class MailArchiveForTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="ai", password="x")
        self.mail = Mail.objects.create(subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m1")
        self.case = Case.objects.create(description="", reporter=self.user)
        self.case.fileOrMail = CaseHasFileOrMail.objects.create(case=self.case, mail=self.mail)
        self.case.save(update_fields=["fileOrMail"])

    def test_the_case_mail_archive_comes_with_its_file_and_mail(self):
        file = File.objects.create(linked_hash=Hash.objects.create(value="h1"), tmp_path="mail.tar.gz")
        stored = MailArchive.objects.create(mail=self.mail, archive=file)
        found = mailtext.mail_archive_for(Case.objects.get(pk=self.case.pk))
        self.assertEqual(found, stored)
        with self.assertNumQueries(0):
            self.assertEqual((found.archive.tmp_path, found.mail.mail_id), ("mail.tar.gz", "m1"))

    def test_no_archive_or_no_mail_gives_none(self):
        self.assertIsNone(mailtext.mail_archive_for(self.case))
        self.assertIsNone(mailtext.mail_archive_for(Case.objects.create(description="", reporter=self.user)))


class TextFromMessageTest(SimpleTestCase):
    def msg(self, plain=None, html=None, charset="utf-8"):
        from email.message import EmailMessage
        m = EmailMessage()
        m["Subject"] = "s"
        if plain is not None:
            m.set_content(plain, charset=charset)
        if html is not None:
            if plain is None:
                m.set_content(html, subtype="html", charset=charset)
            else:
                m.add_alternative(html, subtype="html")
        return m

    def test_plain_part_wins(self):
        self.assertEqual(mailtext.text_from_message(self.msg("plain body", "<p>html body</p>")), "plain body")

    def test_html_reduced_to_text(self):
        html = "<style>p{}</style><p>Hello <b>there</b></p><script>evil()</script><p>bye</p>"
        self.assertEqual(mailtext.text_from_message(self.msg(html=html)), "Hello there bye")

    def test_charset_decoded(self):
        self.assertEqual(mailtext.text_from_message(self.msg("caf\u00e9", charset="iso-8859-1")), "caf\u00e9")

    def test_nothing_usable(self):
        from email.message import EmailMessage
        self.assertEqual(mailtext.text_from_message(EmailMessage()), "")
        self.assertEqual(mailtext.text_from_message(self.msg(html="<script>x</script>")), "")
