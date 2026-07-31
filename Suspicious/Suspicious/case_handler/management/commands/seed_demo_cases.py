"""
Seed the database with fictional demo cases for local / UI testing.

Populates realistic-looking phishing investigation cases for the fictional
company **Eco**, so the React UI (Investigations list, Dashboard) has content
to display without running the full submit → Cortex → finalise pipeline.

Usage (inside the container):
    python manage.py seed_demo_cases              # ~24 cases
    python manage.py seed_demo_cases --count 50
    python manage.py seed_demo_cases --flush      # remove prior demo data first

All rows created here are tagged with a marker in ``Case.description`` so
``--flush`` can remove exactly the demo data and nothing else.
"""

from __future__ import annotations

import random
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from case_handler.lifecycle import LifecycleState
from case_handler.models import Case, CaseHasFileOrMail, Result, Status
from mail_feeder.models import Mail

User = get_user_model()

MARKER = "[demo-seed]"

# Fictional Eco personas (reporters). Spread across regions to exercise the
# region logic; kept in sync with the greenmail mailboxes in the compose override.
PERSONAS = [
    ("elena.voss@eco.example", "Elena", "Voss"),
    ("adaeze.okafor@eco.example", "Adaeze", "Okafor"),
    ("jordan.kim@eco.example", "Jordan", "Kim"),
    ("camila.reyes@eco.example", "Camila", "Reyes"),
    ("haruto.sato@eco.example", "Haruto", "Sato"),
    ("sam.whitfield@eco.example", "Sam", "Whitfield"),
]

# (subject, sender, result)
SAMPLES = [
    ("Your mailbox is almost full - verify now to avoid suspension",
     "it-support@ec0-secure.example", Result.DANGEROUS),
    ("Invoice #4021 overdue - immediate payment required",
     "billing@invoices-eco.example", Result.SUSPICIOUS),
    ("HR: Updated remote-work policy (action required)",
     "hr@eco.example", Result.SAFE),
    ("Security alert: unusual sign-in to your account",
     "no-reply@account-eco-security.example", Result.DANGEROUS),
    ("You have (3) quarantined messages - release now",
     "postmaster@eco-mailguard.example", Result.SUSPICIOUS),
    ("Team lunch next Friday - RSVP",
     "camila.reyes@eco.example", Result.SAFE),
    ("DocuSign: Please review and sign document",
     "dse@docu-sign-eco.example", Result.SUSPICIOUS),
    ("Payroll update - confirm your bank details",
     "payroll@eco-finance.example", Result.DANGEROUS),
    ("Reset your password within 24h",
     "helpdesk@eco-it.example", Result.DANGEROUS),
    ("Weekly newsletter - Eco insights",
     "news@eco.example", Result.SAFE),
    ("Shared document: Q3 forecast.xlsx",
     "jordan.kim@eco.example", Result.INCONCLUSIVE),
    ("Your parcel could not be delivered - reschedule",
     "tracking@parcel-eco.example", Result.SUSPICIOUS),
]

# Plausible score ranges per verdict (0-100 scale).
SCORE_BY_RESULT = {
    Result.SAFE: (5, 25),
    Result.INCONCLUSIVE: (40, 55),
    Result.SUSPICIOUS: (60, 80),
    Result.DANGEROUS: (85, 99),
}

AI_CATEGORIES = ["Phishing", "Spam", "Legitimate", "Malware", "Uncategorized"]


class Command(BaseCommand):
    help = "Seed fictional Eco demo cases for local / UI testing."

    def add_arguments(self, parser):
        parser.add_argument("--count", type=int, default=24,
                            help="Number of demo cases to create (default: 24).")
        parser.add_argument("--flush", action="store_true",
                            help="Delete previously seeded demo cases first.")

    @transaction.atomic
    def handle(self, *args, **opts):
        count = opts["count"]

        if opts["flush"]:
            demo = Case.objects.filter(description__startswith=MARKER)
            mail_ids = list(
                CaseHasFileOrMail.objects.filter(case__in=demo)
                .exclude(mail__isnull=True)
                .values_list("mail_id", flat=True)
            )
            n = demo.count()
            demo.delete()
            Mail.objects.filter(id__in=mail_ids).delete()
            self.stdout.write(self.style.WARNING(f"Flushed {n} demo case(s)."))

        users = []
        for email, first, last in PERSONAS:
            user, _ = User.objects.get_or_create(
                username=email,
                defaults={
                    "email": email,
                    "first_name": first,
                    "last_name": last,
                    "is_active": True,
                },
            )
            users.append(user)

        now = timezone.now()
        created = 0
        for _ in range(count):
            subject, sender, result = random.choice(SAMPLES)
            reporter = random.choice(users)

            age_days = random.randint(0, 120)
            dt = now - timedelta(
                days=age_days,
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
            )

            lo, hi = SCORE_BY_RESULT[result]
            score = round(random.uniform(lo, hi), 1)
            confidence = round(random.uniform(60, 95), 1)

            # Status / lifecycle: recent cases may still be open; dangerous ones
            # are sometimes challenged; the rest are finalised.
            if result == Result.DANGEROUS and random.random() < 0.30:
                status, lifecycle, challenged = (
                    Status.CHALLENGED, LifecycleState.CONTESTED, True,
                )
            elif age_days < 3 and random.random() < 0.5:
                status, lifecycle, challenged = (
                    random.choice([Status.TODO, Status.ONGOING]),
                    LifecycleState.ANALYZING, False,
                )
            else:
                status, lifecycle, challenged = (
                    Status.DONE, LifecycleState.FINALIZED, False,
                )

            mail = Mail.objects.create(
                subject=subject,
                reportedBy=reporter.email,
                date=dt,
                to="suspicious@eco.example",
                mail_from=sender,
                mail_id=str(uuid.uuid4()),
            )

            case = Case.objects.create(
                description=f"{MARKER} {subject}",
                reporter=reporter,
                results=result,
                final_score=score,
                score=score,
                final_confidence=confidence,
                confidence=confidence,
                results_ai=result,
                score_ai=score,
                confidence_ai=confidence,
                category_ai=random.choice(AI_CATEGORIES),
                status=status,
                lifecycle_state=lifecycle,
                is_challenged=challenged,
                challenged_result=(Result.DANGEROUS if challenged else Result.UNCHALLENGED),
                analysis_done=5,
                kpi_counted=True,
            )

            link = CaseHasFileOrMail.objects.create(case=case, mail=mail)
            case.fileOrMail = link
            if lifecycle == LifecycleState.FINALIZED:
                case.finalized_at = dt
            case.save(update_fields=["fileOrMail", "finalized_at"])

            # creation_date is auto_now_add; backdate via a bypassing update().
            Case.objects.filter(pk=case.pk).update(creation_date=dt, last_update=dt)
            created += 1

        self.stdout.write(self.style.SUCCESS(
            f"Created {created} demo case(s) across {len(users)} reporter(s)."
        ))
