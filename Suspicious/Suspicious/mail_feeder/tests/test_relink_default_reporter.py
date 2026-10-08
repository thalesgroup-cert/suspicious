from io import StringIO
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case, CaseHasFileOrMail
from mail_feeder.models import Mail, MailInfo

CREATION = "mail_feeder.utils.user_creation.creation"


def _mail(sender, n):
    return Mail.objects.create(
        subject="s", reportedBy=sender, date=timezone.now(), to="t", mail_id=f"m{n}",
    )


class RelinkDefaultReporterTests(TestCase):
    def setUp(self):
        for target, kwargs in (
            (f"{CREATION}._own_domains", {"return_value": ["corp.example"]}),
            (f"{CREATION}._suspicious_email", {"return_value": "suspicious@corp.example"}),
            (f"{CREATION}.create_ldap_user", {}),
        ):
            p = patch(target, **kwargs)
            p.start()
            self.addCleanup(p.stop)
        self.default = User.objects.create_user("suspicious@corp.example", "suspicious@corp.example")

    def _case(self, sender, n):
        mail = _mail(sender, n)
        case = Case.objects.create(description="d", reporter=self.default)
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save()
        MailInfo.objects.create(user=self.default, mail=mail)
        return case, mail

    def _run(self, *args):
        out = StringIO()
        call_command("relink_default_reporter", *args, stdout=out)
        return out.getvalue()

    def test_dry_run_reports_and_changes_nothing(self):
        case, mail = self._case("jane@uk.corp.example", 1)
        out = self._run()
        self.assertIn("would move 1", out)
        case.refresh_from_db()
        self.assertEqual(case.reporter_id, self.default.id)
        self.assertEqual(MailInfo.objects.get(mail=mail).user_id, self.default.id)
        self.assertFalse(User.objects.filter(username="jane@uk.corp.example").exists())

    def test_apply_moves_case_and_mail_info_to_the_real_reporter(self):
        case, mail = self._case("jane@uk.corp.example", 1)
        outsider, _ = self._case("stranger@elsewhere.example", 2)
        out = self._run("--apply")
        self.assertIn("moved 1", out)
        jane = User.objects.get(username="jane@uk.corp.example")
        case.refresh_from_db()
        self.assertEqual(case.reporter_id, jane.id)
        self.assertEqual(MailInfo.objects.get(mail=mail).user_id, jane.id)
        outsider.refresh_from_db()
        self.assertEqual(outsider.reporter_id, self.default.id)   # not a company address: untouched

    def test_apply_does_not_touch_last_update(self):
        case, _ = self._case("jane@uk.corp.example", 1)
        before = Case.objects.get(pk=case.pk).last_update
        self._run("--apply")
        self.assertEqual(Case.objects.get(pk=case.pk).last_update, before)
