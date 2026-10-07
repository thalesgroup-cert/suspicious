"""Bulk-(re)index cases into the case_search Elasticsearch index.

Run once before enabling the case_search connector, and to repair drift."""
from django.core.management.base import BaseCommand, CommandError
from django.utils.dateparse import parse_date

from case_handler.models import Case
from connectors.contrib.case_search import service
from settings.config import get_section


class Command(BaseCommand):
    help = "Index cases into Elasticsearch (all, or those updated since --since)."

    def add_arguments(self, parser):
        parser.add_argument("--since", help="YYYY-MM-DD: only cases updated on/after this date")

    def handle(self, *args, **opts):
        cases = Case.objects.select_related(*service.CASE_RELATED).order_by("pk")
        if opts["since"]:
            since = parse_date(opts["since"])
            if since is None:
                raise CommandError(f"invalid --since date: {opts['since']!r}")
            cases = cases.filter(last_update__date__gte=since)

        config = get_section("integrations.case_search")
        index = config.get("index") or service.DEFAULT_INDEX
        client = service.get_client(config, timeout=service.INDEX_TIMEOUT * 6)
        service.ensure_index(client, index)
        ok, errors = service.bulk_index(client, index, cases.iterator(chunk_size=500))
        self.stdout.write(f"{ok} indexed, {errors} errors (index {index})")
        if errors:
            raise CommandError(f"{errors} documents failed to index")
