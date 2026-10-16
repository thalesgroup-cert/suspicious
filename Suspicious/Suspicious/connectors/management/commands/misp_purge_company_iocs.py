"""List (and optionally remove) company-linked data already pushed to a MISP event.

The push filters keep company addresses, domains and links out of new pushes;
this command finds what an event received before them. Defaults to the
current monthly event on the secondary (security) instance. Dry run unless
--apply. Deletions are MISP soft deletes, which synchronised instances pick
up; copies that were already pulled elsewhere cannot be recalled.
"""
from django.core.management.base import BaseCommand, CommandError

from connectors.contrib.misp.client import MISPClient
from connectors.contrib.misp.cleanup import scan_event
from connectors.contrib.misp.config_loader import load_misp_settings
from connectors.contrib.misp.internal import company_domains
from connectors.contrib.misp.utils import current_month_event_name


class Command(BaseCommand):
    help = "List company-linked attributes/objects in a MISP event (dry run unless --apply)."

    def add_arguments(self, parser):
        parser.add_argument("--instance", choices=("secondary", "primary"), default="secondary",
                            help="MISP instance to scan (default: secondary, where the monthly event lives)")
        parser.add_argument("--event", help="event info to scan (default: this month's MalSpam event)")
        parser.add_argument("--event-id", help="scan this event id instead of looking one up by name")
        parser.add_argument("--apply", action="store_true", help="delete/rewrite what is listed")

    def handle(self, *args, **opts):
        domains = company_domains()
        if not domains:
            raise CommandError("no company domains configured (Watcher legit list / own domains); "
                               "refusing to scan with an empty filter")

        settings = load_misp_settings()
        config = settings.security if opts["instance"] == "secondary" else settings.suspicious
        misp = MISPClient(config=config).misp

        event_id = opts["event_id"] or self._find_event(misp, opts["event"] or current_month_event_name())
        event = (misp.get_event(event_id) or {}).get("Event")
        if not event:
            raise CommandError(f"event {event_id} not found on the {opts['instance']} instance")

        findings = scan_event(event, domains)
        self.stdout.write(f"event {event['id']} {event.get('info')!r}: {len(findings)} finding(s), "
                          f"{len(domains)} company domain(s) checked")
        for f in findings:
            keep = f" -> {f.keep}" if f.keep else ""
            self.stdout.write(f"  {f.action:7} {f.kind} {f.id} {f.type}: {f.value}{keep}  [{f.reason}]")

        if not opts["apply"]:
            self.stdout.write("dry run; pass --apply to write")
            return

        failed = 0
        for f in findings:
            try:
                if f.kind == "object":
                    response = misp.delete_object(f.id)
                elif f.keep:
                    response = misp.update_attribute({"value": f.keep}, attribute_id=f.id)
                else:
                    response = misp.delete_attribute(f.id)
                if isinstance(response, dict) and response.get("errors"):
                    raise RuntimeError(response["errors"])
            except Exception as exc:  # noqa: BLE001 - keep going, report at the end
                failed += 1
                self.stderr.write(f"{f.kind} {f.id}: {exc}")
        self.stdout.write(f"applied {len(findings) - failed} change(s), failed {failed}")

    @staticmethod
    def _find_event(misp, name):
        results = misp.search(controller="events", eventinfo=name, metadata=True) or []
        ids = [e["Event"]["id"] for e in results if e.get("Event", {}).get("info") == name]
        if not ids:
            raise CommandError(f"no MISP event named {name!r}")
        if len(ids) > 1:
            raise CommandError(f"{len(ids)} events named {name!r} ({', '.join(ids)}); pass --event-id")
        return ids[0]
