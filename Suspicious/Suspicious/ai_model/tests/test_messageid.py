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
        for bad in ("", "   ", "garbage", "<>"):
            self.assertEqual(messageid.normalise(bad), "")

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
