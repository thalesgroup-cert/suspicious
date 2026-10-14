"""Backfill the Elastic SIEM index with existing cases.

Run once after enabling the elastic_siem connector, and to repair drift. Only
cases at or above the connector's min_verdict (or --min-verdict) are sent."""
from django.core.management.base import BaseCommand, CommandError
from django.utils.dateparse import parse_date

from case_handler.models import Case
from connectors.contrib.elastic_siem import service
from connectors.delivery import get_state
from settings.config import get_section

BATCH_SIZE = 500


class Command(BaseCommand):
    help = "Send existing cases to the Elastic SIEM index (those at or above min_verdict)."

    def add_arguments(self, parser):
        parser.add_argument("--since", help="YYYY-MM-DD: only cases updated on/after this date")
        parser.add_argument("--min-verdict", help="override the connector's min_verdict for this run")
        parser.add_argument("--dry-run", action="store_true", help="count only, send nothing")

    def handle(self, *args, **opts):
        if not get_state("elastic_siem").enabled:
            raise CommandError("elastic_siem connector is disabled; enable it first")
        config = dict(get_section("integrations.elastic_siem"))
        if opts["min_verdict"]:
            config["min_verdict"] = opts["min_verdict"]
        try:
            service.validate_config(config)
            threshold = service.min_rank(config)
        except ValueError as exc:
            raise CommandError(str(exc))

        cases = Case.objects.select_related(*service.CASE_RELATED).order_by("pk")
        if opts["since"]:
            since = parse_date(opts["since"])
            if since is None:
                raise CommandError(f"invalid --since date: {opts['since']!r}")
            cases = cases.filter(last_update__date__gte=since)

        client = None if opts["dry_run"] else service.SiemClient(config)
        if client:
            client.ensure_index()

        sent = skipped = failed = 0
        batch = []

        def flush():
            nonlocal sent, failed
            if not batch:
                return
            ok, errors = client.bulk(list(batch)) if client else (len(batch), 0)
            sent, failed = sent + ok, failed + errors
            batch.clear()

        ui_base_url = config.get("ui_base_url") or ""
        for case in cases.iterator(chunk_size=BATCH_SIZE):
            rank = service.case_rank(case)
            if rank is None or rank < threshold:
                skipped += 1
                continue
            batch.append((case.pk, service.build_document(case, "reindex", ui_base_url=ui_base_url)))
            if len(batch) >= BATCH_SIZE:
                flush()
        flush()

        verb = "would be sent" if opts["dry_run"] else "sent"
        self.stdout.write(f"{sent} {verb}, {skipped} skipped, {failed} failed")
        if failed:
            raise CommandError(f"{failed} documents failed to index")
