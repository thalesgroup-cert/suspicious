"""Move cases attributed to the shared default reporter to their real reporter.

Emailed submissions whose sender was not recognised as a company address were
attributed to the shared mailbox user. Once the sender's domain is recognised
(see UserCreationService), this command re-attributes those cases: it sets
Case.reporter and MailInfo.user. Dry run unless --apply. Notifications that
already went to the shared mailbox are not re-sent."""
from collections import Counter

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db import transaction

from case_handler.models import Case
from mail_feeder.models import MailInfo
from mail_feeder.utils.user_creation.creation import UserCreationService, _suspicious_email


class Command(BaseCommand):
    help = "Re-attribute cases of the shared default reporter to the real sender (dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="write the changes")

    def handle(self, *args, **opts):
        default = User.objects.filter(username=_suspicious_email()).first()
        if default is None:
            self.stdout.write("no default reporter user; nothing to do")
            return

        service = UserCreationService()
        cases = Case.objects.filter(reporter=default, fileOrMail__mail__isnull=False).select_related("fileOrMail__mail")
        moved, skipped, failed = 0, 0, 0
        domains = Counter()
        for case in cases.iterator():
            mail = case.fileOrMail.mail
            result = service.email_validator.is_company_email((mail.reportedBy or "").strip().lower())
            if not result.is_valid:
                skipped += 1
                continue
            domains[result.normalized.rsplit("@", 1)[1]] += 1
            if not opts["apply"]:
                moved += 1
                continue
            try:
                user = service.get_or_create_user(result.normalized)
                if user is None or user.pk == default.pk:
                    skipped += 1
                    continue
                with transaction.atomic():
                    # update() on purpose: leave last_update untouched
                    Case.objects.filter(pk=case.pk).update(reporter=user)
                    MailInfo.objects.filter(mail=mail, user=default).update(user=user)
                moved += 1
            except Exception as exc:  # noqa: BLE001 - keep going, report at the end
                failed += 1
                self.stderr.write(f"case {case.pk}: {exc}")

        verb = "moved" if opts["apply"] else "would move"
        self.stdout.write(f"{verb} {moved} case(s), skipped {skipped} (not a company address), failed {failed}")
        for domain, count in domains.most_common(10):
            self.stdout.write(f"  {domain}: {count}")
