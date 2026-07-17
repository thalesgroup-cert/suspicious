from django.core.management.base import BaseCommand
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState
from tasp.tasks import reconcile_case


class Command(BaseCommand):
    help = "Enqueue reconcile_case for every non-terminal case."

    def handle(self, *args, **options):
        terminal = (LifecycleState.FINALIZED, LifecycleState.CONTESTED)
        ids = (
            Case.objects.exclude(lifecycle_state__in=terminal)
            .values_list("id", flat=True)
        )
        count = 0
        for cid in ids:
            reconcile_case.delay(cid)
            count += 1
        self.stdout.write(self.style.SUCCESS(f"Enqueued {count} case(s)."))
