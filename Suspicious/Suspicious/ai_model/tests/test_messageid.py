from collections import defaultdict
from datetime import datetime, timezone as tz

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from ai_model import messageid
from case_handler.models import Case, CaseHasFileOrMail
from mail_feeder.models import Mail, MailHeader


class NormaliseTest(SimpleTestCase):
    def test_normalise(self):
        self.assertEqual(messageid.normalise("  <ABC.123@Mail.Example>  "), "abc.123@mail.example")
        for bad in ("", "   ", "garbage", "<>", "@", "<@x>", "a@", "<@>", "@x.example"):
            self.assertEqual(messageid.normalise(bad), "")

    def test_an_id_above_998_characters_is_dropped(self):
        at_limit = "a" * (998 - len("@x.example")) + "@x.example"
        self.assertEqual(messageid.normalise(f"<{at_limit}>"), at_limit)
        self.assertEqual(messageid.normalise("a" + at_limit), "")

    def test_hash(self):
        import hashlib
        self.assertEqual(messageid.message_id_hash("a@b"), hashlib.sha256(b"a@b").hexdigest())


class MatchCaseTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="u", password="x")
        self.n = 0

    def make(self, headers, subject="Hello", mail_from="", date=datetime(2026, 5, 1, 10, tzinfo=tz.utc)):
        self.n += 1
        d = defaultdict(list)
        for k, v in headers:
            d[k].append(v)
        header = MailHeader.objects.create(header_value=str(d), fuzzy_hash=f"h{self.n}")
        mail = Mail.objects.create(subject=subject, reportedBy="r", date=date, to="t", mail_id=f"m{self.n}",
                                   mail_header=header, mail_from=mail_from)
        case = Case.objects.create(description="", reporter=self.user)
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save(update_fields=["fileOrMail"])
        return case

    def test_message_id_match_is_case_insensitive(self):
        case = self.make([("Message-ID", "<Abc.123@Mail.Example>"), ("Subject", "x")])
        self.make([("Message-ID", "<other.1@mail.example>")])
        self.assertEqual(messageid.match_case("<abc.123@MAIL.example>"), case)

    def test_no_match(self):
        self.make([("Message-ID", "<abc.123@mail.example>")])
        self.assertIsNone(messageid.match_case("<abc.123@elsewhere.example>"))
        self.assertIsNone(messageid.match_case("<nothing@mail.example>"))

    def test_fallback_needs_exactly_one(self):
        kw = dict(sender="Bob <bob@x.example>", date=datetime(2026, 5, 1, 23, 59, tzinfo=tz.utc), subject="hello")
        self.assertIsNone(messageid.match_case("", **kw))
        one = self.make([("From", "Bob <bob@x.example>")])
        self.assertEqual(messageid.match_case("", **kw), one)
        self.make([], mail_from="bob@x.example")
        self.assertIsNone(messageid.match_case("", **kw))

    def test_fallback_other_day_or_sender_does_not_match(self):
        self.make([("From", "bob@x.example")])
        self.assertIsNone(messageid.match_case("", sender="bob@x.example", subject="Hello",
                                               date=datetime(2026, 5, 2, 0, 1, tzinfo=tz.utc)))
        self.assertIsNone(messageid.match_case("", sender="eve@x.example", subject="Hello",
                                               date=datetime(2026, 5, 1, 1, tzinfo=tz.utc)))

    def test_id_only_in_references_does_not_match(self):
        self.make([("Message-ID", "<other@mail.example>"), ("References", "<abc.123@mail.example>"),
                   ("In-Reply-To", "<abc.123@mail.example>")])
        self.assertIsNone(messageid.match_case("<abc.123@mail.example>"))

    def test_duplicate_id_returns_newest_case(self):
        self.make([("Message-ID", "<dup@mail.example>")])
        newest = self.make([("Message-ID", "<dup@mail.example>")])
        self.assertEqual(messageid.match_case("<dup@mail.example>"), newest)

    def test_case_without_mail_or_header_gives_none(self):
        Case.objects.create(description="", reporter=self.user)
        mail = Mail.objects.create(subject="Hello", reportedBy="r", date=datetime(2026, 5, 1, 10, tzinfo=tz.utc),
                                   to="t", mail_id="nh")
        case = Case.objects.create(description="", reporter=self.user)
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save(update_fields=["fileOrMail"])
        self.assertIsNone(messageid.match_case("<abc@mail.example>"))
        self.assertIsNone(messageid.match_case("", sender="a@b.example", subject="Hello",
                                               date=datetime(2026, 5, 1, 9, tzinfo=tz.utc)))

    def test_fallback_non_utc_date_near_day_boundary(self):
        from datetime import timedelta
        case = self.make([("From", "bob@x.example")], date=datetime(2026, 5, 1, 23, 30, tzinfo=tz.utc))
        local = datetime(2026, 5, 2, 1, 0, tzinfo=tz(timedelta(hours=2)))  # 23:00 UTC on May 1
        self.assertEqual(messageid.match_case("", sender="bob@x.example", date=local, subject="Hello"), case)
        late = datetime(2026, 5, 1, 23, 0, tzinfo=tz(timedelta(hours=-2)))  # 01:00 UTC on May 2
        self.assertIsNone(messageid.match_case("", sender="bob@x.example", date=late, subject="Hello"))


class StoredSenderTest(TestCase):
    def test_mail_from_then_the_from_header(self):
        header = MailHeader.objects.create(header_value=str({"From": ["Bob <Bob@X.Example>"]}), fuzzy_hash="s")
        mail = Mail(subject="s", reportedBy="r", to="t", mail_id="s", mail_header=header, mail_from="")
        self.assertEqual(messageid.stored_sender(mail), "bob@x.example")
        mail.mail_from = "Eve <eve@y.example>"
        self.assertEqual(messageid.stored_sender(mail), "eve@y.example")
        self.assertEqual(messageid.stored_sender(Mail(mail_from="")), "")
