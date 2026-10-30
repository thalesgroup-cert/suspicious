import io
import tarfile
from types import SimpleNamespace

from django.core.files.base import ContentFile
from django.test import SimpleTestCase

from connectors.contrib.ai_model import mailtext
from connectors.contrib.ai_model.mailtext import read_archive_body


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

    def test_garbage_and_missing_archives_give_none(self):
        self.assertIsNone(read_archive_body(archive(b"this is not a tar file")))
        self.assertIsNone(read_archive_body(SimpleNamespace(archive=None)))
        self.assertIsNone(read_archive_body(None))
