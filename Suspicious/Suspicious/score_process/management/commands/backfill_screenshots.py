"""Backfill AnalyzerReport screenshots for historical Success reports from
screenshot analyzers (Lookyloo / urlscan). Idempotent; does not re-score."""
from django.core.management.base import BaseCommand
from django.db.models import Q

from cortex_job.models import AnalyzerReport
from score_process.scoring.screenshots import registry


class Command(BaseCommand):
    help = "Capture + store screenshots for existing analyzer reports that have none."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--limit", type=int, default=None)

    def handle(self, *args, **opts):
        qs = (AnalyzerReport.objects
              .filter(status="Success", screenshot_key="")
              .filter(Q(analyzer__name__icontains="lookyloo")
                      | Q(analyzer__name__icontains="urlscan"))
              .select_related("analyzer", "url", "domain", "ip")
              .order_by("id"))
        if opts["limit"]:
            qs = qs[:opts["limit"]]

        scanned = stored = 0
        for report in qs.iterator(chunk_size=200):
            scanned += 1
            png = registry.capture(report)
            if not png:
                continue
            if opts["dry_run"]:
                stored += 1
                continue
            try:
                registry.store(report, png)
                stored += 1
            except Exception as exc:  # noqa: BLE001
                self.stderr.write(f"report {report.id}: store failed: {exc}")

        verb = "would store" if opts["dry_run"] else "stored"
        self.stdout.write(f"scanned {scanned}, {verb} {stored} screenshots")
