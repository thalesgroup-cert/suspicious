from datetime import datetime, timezone
from email.message import EmailMessage
from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.ai_model import imap_sync
from connectors.contrib.ai_model.imap_sync import FolderUnavailable, ReviewMail, read_folder
from connectors.contrib.ai_model.tests.fake_imap import FakeImap

FOLDER = "2_CLASSIC_PHISHING"


def inner(n=1, body="Please verify your account now."):
    msg = EmailMessage()
    msg["From"] = f"Bad Actor <bad{n}@evil.example>"
    msg["To"] = "victim@meridian.example"
    msg["Subject"] = f"Urgent {n}"
    msg["Date"] = "Mon, 05 Oct 2026 10:00:00 +0200"
    msg["Message-ID"] = f"<ID.{n}@Evil.Example>"
    msg.set_content(body)
    return msg


def forward(n=1, **kw):
    outer = EmailMessage()
    outer["From"] = "analyst@meridian.example"
    outer["Subject"] = "Fwd: review"
    outer["Message-ID"] = f"<outer.{n}@meridian.example>"
    outer.set_content("see attached")
    outer.add_attachment(inner(n, **kw))
    return outer.as_bytes()


def not_forward():
    msg = inner(99)
    return msg.as_bytes()


def fake(messages, uidvalidity=7, **kw):
    return FakeImap({FOLDER: {"uidvalidity": uidvalidity, "messages": messages}}, **kw)


class ReadFolderTest(SimpleTestCase):
    def test_reads_forwarded_mail_from_inner_message(self):
        imap = fake({3: forward(1)})
        mails, skipped, uidvalidity = read_folder(imap, FOLDER, since_uid=0, limit=10)
        self.assertEqual((skipped, uidvalidity), (0, 7))
        self.assertEqual(len(mails), 1)
        mail = mails[0]
        self.assertIsInstance(mail, ReviewMail)
        self.assertEqual((mail.folder, mail.uidvalidity, mail.uid), (FOLDER, 7, 3))
        self.assertEqual(mail.message_id, "id.1@evil.example")
        self.assertEqual(mail.sender, "bad1@evil.example")
        self.assertEqual(mail.subject, "Urgent 1")
        self.assertEqual(mail.date, datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc))
        self.assertEqual(mail.text, "Please verify your account now.")

    def test_select_is_read_only_and_nothing_is_modified(self):
        imap = fake({1: forward(1), 2: forward(2)})
        read_folder(imap, FOLDER, since_uid=0, limit=10)
        selects = [c for c in imap.commands if c[0] == "SELECT"]
        self.assertEqual(selects, [("SELECT", FOLDER, True)])
        for command in imap.commands:
            self.assertNotIn(command[0], {"STORE", "COPY", "MOVE", "EXPUNGE", "APPEND", "DELETE"})
            if command[0] == "UID":
                self.assertIn(command[1], {"SEARCH", "FETCH"})
                if command[1] == "FETCH":
                    self.assertEqual(command[3], "(BODY.PEEK[])")

    def test_only_uids_above_since_uid_lowest_first_at_most_limit(self):
        imap = fake({u: forward(u) for u in (2, 5, 6, 9, 11)})
        mails, _, _ = read_folder(imap, FOLDER, since_uid=5, limit=2)
        self.assertEqual([m.uid for m in mails], [6, 9])
        fetched = [c[2] for c in imap.commands if c[:2] == ("UID", "FETCH")]
        self.assertEqual(fetched, ["6", "9"])

    def test_search_echoing_the_last_uid_fetches_nothing(self):
        imap = fake({4: forward(4)}, search_extra=(4,))
        self.assertEqual(read_folder(imap, FOLDER, since_uid=4, limit=10), ([], 0, 7))
        self.assertFalse([c for c in imap.commands if c[:2] == ("UID", "FETCH")])

    def test_not_forward_unparseable_and_oversize_are_skipped(self):
        imap = fake(
            {1: not_forward(), 2: b"", 3: b"", 4: forward(4)},
            fetch_override={
                2: [None],  # no literal: unparseable answer
                3: [(b"3 (UID 3 BODY[] {30000000}", b"truncated"), b")"],
            },
        )
        mails, skipped, _ = read_folder(imap, FOLDER, since_uid=0, limit=10)
        self.assertEqual([m.uid for m in mails], [4])
        self.assertEqual(skipped, 3)

    def test_oversize_by_length_when_no_literal_size(self):
        imap = fake({1: b""}, fetch_override={1: [(b"1 (UID 1 BODY[]", forward(1)), b")"]})
        with mock.patch.object(imap_sync, "MAX_MESSAGE_BYTES", 10):
            self.assertEqual(read_folder(imap, FOLDER, since_uid=0, limit=10), ([], 1, 7))

    def test_parse_failure_is_skipped_and_logged_without_mail_data(self):
        imap = fake({1: forward(1)})
        with mock.patch.object(imap_sync, "text_from_message", side_effect=ValueError("secret body")), \
                self.assertLogs(imap_sync.logger, "INFO") as logs:
            self.assertEqual(read_folder(imap, FOLDER, since_uid=0, limit=10), ([], 1, 7))
        joined = "\n".join(logs.output)
        self.assertIn("ValueError", joined)
        self.assertIn(FOLDER, joined)
        self.assertNotIn("secret body", joined)
        self.assertNotIn("evil.example", joined)

    def test_uidvalidity_is_returned(self):
        imap = fake({1: forward(1)}, uidvalidity=42)
        self.assertEqual(read_folder(imap, FOLDER, since_uid=0, limit=10)[2], 42)

    def test_empty_folder(self):
        self.assertEqual(read_folder(fake({}), FOLDER, since_uid=0, limit=10), ([], 0, 7))

    def test_missing_folder_raises(self):
        with self.assertRaises(FolderUnavailable) as ctx:
            read_folder(fake({}), "1_SPAM", since_uid=0, limit=10)
        self.assertIn("1_SPAM", str(ctx.exception))
        self.assertNotIn("NONEXISTENT", str(ctx.exception))

    def test_select_error_raises(self):
        imap = fake({})
        with mock.patch.object(imap, "select", side_effect=imap_sync.imaplib.IMAP4.error("BAD")):
            with self.assertRaises(FolderUnavailable):
                read_folder(imap, FOLDER, since_uid=0, limit=10)


class ConnectTest(SimpleTestCase):
    def test_ssl_verifies_certificates_and_logs_in(self):
        with mock.patch.object(imap_sync.imaplib, "IMAP4_SSL") as ssl_cls:
            client = imap_sync.connect("imap.example", 993, "u", "p", True)
        self.assertIs(client, ssl_cls.return_value)
        args, kwargs = ssl_cls.call_args
        self.assertEqual(args, ("imap.example", 993))
        self.assertEqual(kwargs["timeout"], 30)
        self.assertEqual(kwargs["ssl_context"].verify_mode, imap_sync.ssl.CERT_REQUIRED)
        client.login.assert_called_once_with("u", "p")

    def test_plain(self):
        with mock.patch.object(imap_sync.imaplib, "IMAP4") as plain_cls:
            client = imap_sync.connect("imap.example", 143, "u", "p", False, timeout=5)
        plain_cls.assert_called_once_with("imap.example", 143, timeout=5)
        client.login.assert_called_once_with("u", "p")

    def test_login_failure_closes_and_reraises(self):
        error = imap_sync.imaplib.IMAP4.error
        with mock.patch.object(imap_sync.imaplib, "IMAP4") as plain_cls:
            plain_cls.return_value.login.side_effect = error("denied")
            with self.assertRaises(error):
                imap_sync.connect("imap.example", 143, "u", "p", False)
        plain_cls.return_value.shutdown.assert_called_once()
