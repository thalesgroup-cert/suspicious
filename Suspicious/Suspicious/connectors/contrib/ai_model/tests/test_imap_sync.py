from datetime import datetime, timezone
from email.message import EmailMessage
from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.ai_model import imap_sync
from connectors.contrib.ai_model.imap_sync import (
    FolderUnavailable,
    ImapConnectionLost,
    ReviewMail,
    read_folder,
)
from connectors.contrib.ai_model.tests.fake_imap import FakeImap

FOLDER = "2_CLASSIC_PHISHING"


_DATE = "Mon, 05 Oct 2026 10:00:00 +0200"


def inner(n=1, body="Please verify your account now.", date=_DATE, attach=()):
    msg = EmailMessage()
    msg["From"] = f"Bad Actor <bad{n}@evil.example>"
    msg["To"] = "victim@meridian.example"
    msg["Subject"] = f"Urgent {n}"
    if date is not None:
        msg["Date"] = date
    msg["Message-ID"] = f"<ID.{n}@Evil.Example>"
    msg.set_content(body)
    for message in attach:
        msg.add_attachment(message)
    return msg


def forward(n=1, *, extra=(), **kw):
    outer = EmailMessage()
    outer["From"] = "analyst@meridian.example"
    outer["Subject"] = "Fwd: review"
    outer["Message-ID"] = f"<outer.{n}@meridian.example>"
    outer.set_content("see attached")
    outer.add_attachment(inner(n, **kw))
    for message in extra:
        outer.add_attachment(message)
    return outer.as_bytes()


def not_forward():
    msg = inner(99)
    return msg.as_bytes()


def fake(messages, uidvalidity=7, **kw):
    return FakeImap({FOLDER: {"uidvalidity": uidvalidity, "messages": messages}}, **kw)


class ReadFolderTest(SimpleTestCase):
    def test_reads_forwarded_mail_from_inner_message(self):
        imap = fake({3: forward(1)})
        mails, skipped, uidvalidity, last_uid = read_folder(imap, FOLDER, since_uid=0, limit=10)
        self.assertEqual((skipped, uidvalidity, last_uid), (0, 7, 3))
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
        self.assertEqual(selects, [("SELECT", f'"{FOLDER}"', True)])
        for command in imap.commands:
            self.assertNotIn(command[0], {"STORE", "COPY", "MOVE", "EXPUNGE", "APPEND", "DELETE"})
            if command[0] == "UID":
                self.assertIn(command[1], {"SEARCH", "FETCH"})
                if command[1] == "FETCH":
                    self.assertIn(command[3], {"(BODY.PEEK[])", "(RFC822.SIZE)"})

    def test_only_uids_above_since_uid_lowest_first_at_most_limit(self):
        imap = fake({u: forward(u) for u in (2, 5, 6, 9, 11)})
        mails, _, _, last_uid = read_folder(imap, FOLDER, since_uid=5, limit=2)
        self.assertEqual([m.uid for m in mails], [6, 9])
        self.assertEqual(last_uid, 9)
        fetched = [c[2] for c in imap.commands if c[:2] == ("UID", "FETCH") and c[3] == "(BODY.PEEK[])"]
        self.assertEqual(fetched, ["6", "9"])
        self.assertIn(("UID", "FETCH", "6,9", "(RFC822.SIZE)"), imap.commands)

    def test_search_echoing_the_last_uid_fetches_nothing(self):
        imap = fake({4: forward(4)}, search_extra=(4,))
        self.assertEqual(read_folder(imap, FOLDER, since_uid=4, limit=10), ([], 0, 7, 4))
        self.assertFalse([c for c in imap.commands if c[:2] == ("UID", "FETCH")])

    def test_not_forward_unparseable_and_oversize_are_skipped(self):
        imap = fake(
            {1: not_forward(), 2: b"", 3: b"", 4: forward(4)},
            fetch_override={
                2: [None],  # no literal: unparseable answer
                3: [(b"3 (UID 3 BODY[] {30000000}", b"truncated"), b")"],
            },
        )
        mails, skipped, _, last_uid = read_folder(imap, FOLDER, since_uid=0, limit=10)
        self.assertEqual([m.uid for m in mails], [4])
        self.assertEqual(last_uid, 4)
        self.assertEqual(skipped, 3)

    def test_oversize_by_length_when_no_literal_size(self):
        imap = fake({1: b""}, fetch_override={1: [(b"1 (UID 1 BODY[]", forward(1)), b")"]})
        with mock.patch.object(imap_sync, "MAX_MESSAGE_BYTES", 10):
            self.assertEqual(read_folder(imap, FOLDER, since_uid=0, limit=10), ([], 1, 7, 1))

    def test_parse_failure_is_skipped_and_logged_without_mail_data(self):
        imap = fake({1: forward(1)})
        with mock.patch.object(imap_sync, "text_from_message", side_effect=ValueError("secret body")), \
                self.assertLogs(imap_sync.logger, "INFO") as logs:
            self.assertEqual(read_folder(imap, FOLDER, since_uid=0, limit=10), ([], 1, 7, 1))
        joined = "\n".join(logs.output)
        self.assertIn("ValueError", joined)
        self.assertIn(FOLDER, joined)
        self.assertNotIn("secret body", joined)
        self.assertNotIn("evil.example", joined)

    def test_uidvalidity_is_returned(self):
        imap = fake({1: forward(1)}, uidvalidity=42)
        self.assertEqual(read_folder(imap, FOLDER, since_uid=0, limit=10)[2], 42)

    def test_skipped_tail_still_advances_last_uid(self):
        imap = fake({1: forward(1), 2: not_forward(), 3: not_forward()})
        mails, skipped, _, last_uid = read_folder(imap, FOLDER, since_uid=0, limit=10)
        self.assertEqual(([m.uid for m in mails], skipped, last_uid), ([1], 2, 3))

    def test_changed_uidvalidity_rereads_from_start_in_same_call(self):
        imap = fake({1: forward(1), 2: forward(2)}, uidvalidity=8)
        mails, _, uidvalidity, last_uid = read_folder(
            imap, FOLDER, since_uid=2, limit=10, known_uidvalidity=7)
        self.assertEqual(([m.uid for m in mails], uidvalidity, last_uid), ([1, 2], 8, 2))
        self.assertEqual(sum(c[0] == "SELECT" for c in imap.commands), 1)

    def test_same_uidvalidity_keeps_since_uid(self):
        imap = fake({1: forward(1), 2: forward(2)})
        mails, _, _, _ = read_folder(imap, FOLDER, since_uid=1, limit=10, known_uidvalidity=7)
        self.assertEqual([m.uid for m in mails], [2])

    def test_folder_name_is_quoted(self):
        name = 'Review "A" \\ 2'
        imap = FakeImap({name: {"uidvalidity": 7, "messages": {1: forward(1)}}})
        mails, _, _, _ = read_folder(imap, name, since_uid=0, limit=10)
        self.assertEqual([m.folder for m in mails], [name])
        self.assertEqual(imap.commands[0], ("SELECT", '"Review \\"A\\" \\\\ 2"', True))

    def test_folder_with_space(self):
        imap = FakeImap({"2 CLONE": {"uidvalidity": 7, "messages": {1: forward(1)}}})
        self.assertEqual(len(read_folder(imap, "2 CLONE", since_uid=0, limit=10)[0]), 1)
        self.assertEqual(imap.commands[0], ("SELECT", '"2 CLONE"', True))

    def test_size_precheck_skips_without_downloading(self):
        imap = fake({1: forward(1), 2: forward(2)}, sizes={2: 30_000_000})
        mails, skipped, _, last_uid = read_folder(imap, FOLDER, since_uid=0, limit=10)
        self.assertEqual(([m.uid for m in mails], skipped, last_uid), ([1], 1, 2))
        self.assertNotIn(("UID", "FETCH", "2", "(BODY.PEEK[])"), imap.commands)

    def test_size_precheck_error_falls_back_to_the_download_check(self):
        imap = fake({1: forward(1)}, errors={"SIZE": imap_sync.imaplib.IMAP4.error("BAD")})
        self.assertEqual(len(read_folder(imap, FOLDER, since_uid=0, limit=10)[0]), 1)

    def test_nested_forward_labels_the_outermost_and_lists_inner_ids(self):
        deepest = inner(3)
        middle = inner(2, attach=(deepest,))
        imap = fake({1: forward(1, attach=(middle,))})
        mail = read_folder(imap, FOLDER, since_uid=0, limit=10)[0][0]
        self.assertEqual(mail.message_id, "id.1@evil.example")
        self.assertEqual(mail.subject, "Urgent 1")
        self.assertEqual(mail.text, "Please verify your account now.")
        self.assertEqual(mail.inner_message_ids, ("id.2@evil.example", "id.3@evil.example"))

    def test_sibling_attachments_first_wins(self):
        imap = fake({1: forward(1, extra=(inner(2),))})
        mail = read_folder(imap, FOLDER, since_uid=0, limit=10)[0][0]
        self.assertEqual((mail.message_id, mail.inner_message_ids), ("id.1@evil.example", ()))

    def test_missing_or_invalid_date_is_none(self):
        for date in (None, "not a date"):
            imap = fake({1: forward(1, date=date)})
            self.assertIsNone(read_folder(imap, FOLDER, since_uid=0, limit=10)[0][0].date, date)

    def test_naive_date_is_utc(self):
        imap = fake({1: forward(1, date="Mon, 05 Oct 2026 10:00:00 -0000")})
        mail = read_folder(imap, FOLDER, since_uid=0, limit=10)[0][0]
        self.assertEqual(mail.date, datetime(2026, 10, 5, 10, 0, tzinfo=timezone.utc))

    def test_forbidden_characters_in_folder_name_send_nothing(self):
        for name in ('X"\r\nA001 DELETE INBOX', "A\x00B", "Bo\u00eete", "A\x7fB"):
            imap = fake({})
            with self.assertRaises(FolderUnavailable) as ctx:
                read_folder(imap, name, since_uid=0, limit=10)
            self.assertEqual(imap.commands, [])
            message = str(ctx.exception)
            self.assertFalse(any(ord(c) < 0x20 or ord(c) >= 0x7f for c in message), message)

    def test_fetch_error_on_one_uid_is_skipped(self):
        imap = fake({1: forward(1), 2: forward(2)}, errors={1: imap_sync.imaplib.IMAP4.error("NO")})
        mails, skipped, _, last_uid = read_folder(imap, FOLDER, since_uid=0, limit=10)
        self.assertEqual(([m.uid for m in mails], skipped, last_uid), ([2], 1, 2))

    def test_search_error_is_folder_unavailable(self):
        imap = fake({1: forward(1)}, errors={"SEARCH": imap_sync.imaplib.IMAP4.error("BAD")})
        with self.assertRaises(FolderUnavailable):
            read_folder(imap, FOLDER, since_uid=0, limit=10)

    def test_connection_loss_anywhere_is_fatal(self):
        abort = imap_sync.imaplib.IMAP4.abort("socket error: secret")
        for where, exc in (("SELECT", abort), ("SEARCH", TimeoutError("t")), ("SIZE", OSError("o")),
                           (1, abort), (1, ConnectionResetError("r"))):
            imap = fake({1: forward(1)}, errors={where: exc})
            with self.assertRaises(ImapConnectionLost) as ctx:
                read_folder(imap, FOLDER, since_uid=0, limit=10)
            self.assertEqual(str(ctx.exception), type(exc).__name__)

    def test_garbage_search_tokens_are_ignored(self):
        imap = fake({2: forward(2)})
        real_uid = imap.uid
        answer = ("OK", [b"2 junk", None, b"(x) *"])
        with mock.patch.object(imap, "uid", side_effect=lambda c, *a: answer if c == "SEARCH" else real_uid(c, *a)):
            mails, skipped, _, last_uid = read_folder(imap, FOLDER, since_uid=0, limit=10)
        self.assertEqual(([m.uid for m in mails], skipped, last_uid), ([2], 0, 2))

    def test_folder_name_in_errors_is_capped(self):
        for name in ("A" * 300, "A" * 300 + "\n"):
            with self.assertRaises(FolderUnavailable) as ctx:
                read_folder(fake({}), name, since_uid=0, limit=10)
            self.assertLessEqual(len(str(ctx.exception).split(":")[0]), 64)
            self.assertNotIn("A" * 65, str(ctx.exception))

    def test_empty_folder(self):
        self.assertEqual(read_folder(fake({}), FOLDER, since_uid=3, limit=10), ([], 0, 7, 3))

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
        self.assertTrue(kwargs["ssl_context"].check_hostname)
        client.login.assert_called_once_with("u", "p")

    def test_plain(self):
        with mock.patch.object(imap_sync.imaplib, "IMAP4") as plain_cls:
            client = imap_sync.connect("imap.example", 143, "u", "p", False, timeout=5)
        plain_cls.assert_called_once_with("imap.example", 143, timeout=5)
        client.login.assert_called_once_with("u", "p")

    def test_login_failure_closes_and_carries_only_the_class_name(self):
        error = imap_sync.imaplib.IMAP4.error
        with mock.patch.object(imap_sync.imaplib, "IMAP4") as plain_cls:
            plain_cls.return_value.login.side_effect = error(
                "b'[AUTHENTICATIONFAILED] Dovecot ready. bad password hunter2 for u'")
            with self.assertRaises(imap_sync.ImapLoginFailed) as ctx:
                imap_sync.connect("imap.example", 143, "u", "hunter2", False)
        plain_cls.return_value.shutdown.assert_called_once()
        self.assertEqual(str(ctx.exception), "error")
        self.assertIsNone(ctx.exception.__cause__)
        self.assertTrue(ctx.exception.__suppress_context__)


class LoginFailedTest(SimpleTestCase):
    def test_a_login_failure_is_not_retried(self):
        self.assertIs(imap_sync.ImapLoginFailed("error").retryable, False)


class TlsFailedTest(SimpleTestCase):
    """Fix wave 8: a TLS failure is its own non-retryable error carrying the class name only."""

    def test_a_certificate_failure_raises_imap_tls_failed(self):
        import ssl
        error = ssl.SSLCertVerificationError("certificate verify failed: self-signed imap.corp.example")
        with mock.patch.object(imap_sync.imaplib, "IMAP4_SSL", side_effect=error):
            with self.assertRaises(imap_sync.ImapTlsFailed) as ctx:
                imap_sync.connect("imap.corp.example", 993, "u", "p", True)
        self.assertEqual(str(ctx.exception), "SSLCertVerificationError")
        self.assertIs(ctx.exception.retryable, False)
        self.assertIsNone(ctx.exception.__cause__)
        self.assertTrue(ctx.exception.__suppress_context__)

    def test_other_ssl_errors_too(self):
        import ssl
        with mock.patch.object(imap_sync.imaplib, "IMAP4_SSL", side_effect=ssl.SSLError("wrong version")):
            with self.assertRaises(imap_sync.ImapTlsFailed) as ctx:
                imap_sync.connect("imap.example", 993, "u", "p", True)
        self.assertEqual(str(ctx.exception), "SSLError")


class SkipLogTest(SimpleTestCase):
    def test_a_skipped_mail_log_shows_the_folder_in_its_short_form(self):
        folder = "INBOX." + "x" * 80
        imap = FakeImap({folder: {"uidvalidity": 1, "messages": {1: b"anything"}}})
        with mock.patch.object(imap_sync, "_review_mail", side_effect=ValueError("bad")), \
                self.assertLogs("connectors.contrib.ai_model", "INFO") as logs:
            read_folder(imap, folder, since_uid=0, limit=10)
        line = next(m for m in logs.output if "skipped a mail" in m)
        self.assertIn(imap_sync._shown(folder), line)
        self.assertNotIn(folder, line)
