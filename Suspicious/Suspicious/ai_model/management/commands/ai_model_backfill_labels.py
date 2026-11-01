"""Backfill the label ledger from what already exists: a verdict row for every case an analyst
last updated, a proposal row for every challenged case, and (--folders) the whole review folders
with no per-run cap and no time budget. Idempotent. Prints counts only, never mail data."""
from django.core.management.base import BaseCommand, CommandError

from ai_model import ledger
from ai_model.models import LabelRecord
from case_handler.models import Case, ProposedVerdict


class Command(BaseCommand):
    help = (
        "Record analyst verdict and challenge proposal rows for existing cases; with --folders also "
        "sync every review folder uncapped. --dry-run writes nothing and prints the counts. Needs "
        "the ai_model connector enabled."
    )

    def add_arguments(self, parser):
        parser.add_argument("--folders", action="store_true",
                            help="also run the review-folder sync without the per-run cap and time budget")
        parser.add_argument("--dry-run", action="store_true", help="write nothing, print what would be created")

    def handle(self, *args, **opts):
        if not ledger.enabled():
            raise CommandError("the ai_model connector is disabled")
        dry = opts["dry_run"]
        connector = None
        if opts["folders"] and not dry:
            from connectors.registry import registry
            connector = registry.instantiate("ai_model")
            if not connector.config.get("imap_host"):
                raise CommandError("no imap_host configured for the ai_model connector")

        verdicts = proposals = 0
        for case in Case.objects.filter(last_update_by__isnull=False).select_related("last_update_by").iterator():
            if dry:
                verdicts += case.results in LabelRecord.LabelClass.values and not self._has(
                    case, LabelRecord.Source.ANALYST_VERDICT, case.results)
            else:
                verdicts += ledger.record_verdict(case, case.last_update_by, case.results) is not None
        for case in Case.objects.exclude(challenge_proposed_result="").iterator():
            proposed = case.challenge_proposed_result
            # record_challenge always appends, so the repeat is skipped here
            if proposed not in ProposedVerdict.values or self._has(case, LabelRecord.Source.CHALLENGE, proposed):
                continue
            proposals += 1
            if not dry:
                ledger.record_challenge(case, proposed)
        verb = "would create" if dry else "created"
        self.stdout.write(f"{verb} {verdicts} verdict row(s), {proposals} proposal row(s)")

        if opts["folders"]:
            if dry:
                self.stdout.write("folders: not read in a dry run")
            else:
                before = LabelRecord.objects.filter(source=LabelRecord.Source.IMAP_FOLDER).count()
                connector.sync(unlimited=True)
                after = LabelRecord.objects.filter(source=LabelRecord.Source.IMAP_FOLDER).count()
                self.stdout.write(f"folders synced: {after - before} folder row(s) created")

    @staticmethod
    def _has(case, source, label_class) -> bool:
        return LabelRecord.objects.filter(
            case=case, source=source, label_class=label_class, status=LabelRecord.Status.ACTIVE).exists()
