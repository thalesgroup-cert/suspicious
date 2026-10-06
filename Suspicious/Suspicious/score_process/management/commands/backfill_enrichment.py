"""Backfill AnalyzerReport.enrichment for historical Success reports.
Display-only; does NOT re-score. Idempotent."""
from django.core.management.base import BaseCommand

from cortex_job.models import AnalyzerReport
from score_process.scoring.enrichment.registry import enrich


class Command(BaseCommand):
    help = "Extract enrichment for existing analyzer reports that have none."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--limit", type=int, default=None)

    def handle(self, *args, **opts):
        qs = (AnalyzerReport.objects
              .filter(enrichment__isnull=True, status="Success")
              .select_related("analyzer", "ip", "url", "hash", "domain", "file",
                              "mail", "mail_body", "mail_header")
              .order_by("id"))
        if opts["limit"]:
            qs = qs[:opts["limit"]]

        scanned = written = staged = 0
        batch = []
        for report in qs.iterator(chunk_size=500):
            scanned += 1
            e = enrich(report)
            if e is None:
                continue
            report.enrichment = e
            batch.append(report)
            staged += 1
            if len(batch) >= 500 and not opts["dry_run"]:
                AnalyzerReport.objects.bulk_update(batch, ["enrichment"])
                written += len(batch)
                batch = []
        if batch and not opts["dry_run"]:
            AnalyzerReport.objects.bulk_update(batch, ["enrichment"])
            written += len(batch)

        if opts["dry_run"]:
            self.stdout.write(f"scanned {scanned}, would write {staged} enrichment rows")
        else:
            self.stdout.write(f"scanned {scanned}, wrote {written} enrichment rows")
