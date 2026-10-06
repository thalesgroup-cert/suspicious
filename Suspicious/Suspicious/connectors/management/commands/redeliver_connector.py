"""Re-emit an event for cases whose last delivery to a connector did not succeed.

Deliveries that exhaust their retries (or are skipped by an open circuit
breaker) are otherwise lost. Re-emission goes through the normal dispatch path,
so breaker, ledger and retries all apply; connectors deduplicate, so running
this twice is safe.
"""
import re
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from case_handler.models import Case
from connectors.dispatch import emit
from connectors.models import ConnectorDelivery
from connectors.registry import registry

_UNITS = {"h": "hours", "d": "days"}


def _parse_since(value: str) -> timedelta:
    m = re.fullmatch(r"(\d+)([hd])", value)
    if not m:
        raise CommandError("--since must look like 6h or 2d")
    return timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})


class Command(BaseCommand):
    help = "Re-emit case_finalised for cases whose latest delivery to a connector failed or was skipped."

    def add_arguments(self, parser):
        parser.add_argument("connector")
        parser.add_argument("--event", default="case_finalised")
        parser.add_argument("--since", help="only look at deliveries newer than this, e.g. 6h or 2d")
        parser.add_argument("--min-age", type=int, default=300,
                            help="seconds; newer rows are left to the running retry (default 300)")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **opts):
        name = opts["connector"]
        if name not in registry.names():
            raise CommandError(f"unknown connector {name!r}")

        rows = ConnectorDelivery.objects.filter(
            connector=name, event=opts["event"], case_id__isnull=False
        ).order_by("id")
        if opts["since"]:
            rows = rows.filter(created_at__gte=timezone.now() - _parse_since(opts["since"]))

        latest = {r.case_id: r for r in rows}  # last row per case wins
        cutoff = timezone.now() - timedelta(seconds=opts["min_age"])
        todo = sorted(
            cid for cid, r in latest.items()
            if r.status != ConnectorDelivery.STATUS_SUCCESS and r.created_at <= cutoff
        )

        self.stdout.write(f"{len(todo)} case(s) to redeliver to {name}: {todo}")
        if opts["dry_run"]:
            return
        for case in Case.objects.filter(pk__in=todo):
            emit(opts["event"], case)
