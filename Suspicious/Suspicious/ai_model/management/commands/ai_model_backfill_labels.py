"""Backfill the label ledger from what already exists: a verdict row for every case an analyst
last updated that has no verdict row yet, a proposal row for every challenged case, a late case
match for folder rows that matched no case, and (--folders) the whole review folders with no
per-run cap and no time budget. Prints counts only, never mail data.

History before the ledger cannot tell an analyst's edit from a later re-score (Redo analysis keeps
last_update_by), so a backfilled verdict is the case's current class under its last editor, dated
at the case's last update. A case that already has a verdict row (any status) is skipped, so the
backfill never supersedes a verdict recorded live.

Idempotent: a rerun adds nothing for what is recorded. A database error in the verdict or
proposal loops is not caught: the command fails loudly and a rerun continues."""
from django.core.management.base import BaseCommand, CommandError

from ai_model import ledger
from ai_model.messageid import match_case
from ai_model.models import LabelRecord
from case_handler.models import Case, ProposedVerdict
from connectors.contrib.ai_model import imap_sync
from connectors.contrib.ai_model.connector import LabelSyncIncomplete
from connectors.providers import ProviderUnavailable

CHUNK = 500
RELATED = ("last_update_by", "fileOrMail__mail__mail_header")


class Command(BaseCommand):
    help = (
        "Record analyst verdict and challenge proposal rows for existing cases; with --folders "
        "also sync every review folder uncapped. --dry-run writes nothing and prints the counts. "
        "Needs the ai_model connector enabled."
    )

    def add_arguments(self, parser):
        parser.add_argument("--folders", action="store_true",
                            help="also sync the review folders without the per-run cap and budget")
        parser.add_argument("--dry-run", action="store_true",
                            help="write nothing, print what would be created")

    def handle(self, *args, **opts):
        if not ledger.enabled():
            raise CommandError("the ai_model connector is disabled")
        dry = opts["dry_run"]
        connector = None
        if opts["folders"]:
            from connectors.registry import registry
            connector = registry.instantiate("ai_model")
            if not connector.config.get("imap_host"):
                raise CommandError("no imap_host configured for the ai_model connector")

        verdicts = proposals = 0
        cases = Case.objects.filter(last_update_by__isnull=False).select_related(*RELATED)
        for case in cases.iterator(chunk_size=CHUNK):
            if case.results not in LabelRecord.LabelClass.values:
                continue
            if LabelRecord.objects.filter(case=case, source=LabelRecord.Source.ANALYST_VERDICT).exists():
                continue  # recorded live or by an earlier backfill: never rewrite it
            verdicts += 1
            if not dry:
                ledger.record_verdict(case, case.last_update_by, case.results, observed_at=case.last_update)
        challenged = Case.objects.exclude(challenge_proposed_result="").select_related(*RELATED)
        for case in challenged.iterator(chunk_size=CHUNK):
            proposed = case.challenge_proposed_result
            # record_challenge always appends, so an identical proposal is skipped here
            if proposed not in ProposedVerdict.values:
                continue
            if self._has(case, LabelRecord.Source.CHALLENGE, proposed):
                continue
            proposals += 1
            if not dry:
                ledger.record_challenge(case, proposed)
        verb = "would create" if dry else "created"
        self.stdout.write(f"{verb} {verdicts} verdict row(s), {proposals} proposal row(s)")
        rematched = self._rematch(dry)
        self.stdout.write(f"{'would re-match' if dry else 're-matched'} {rematched} folder row(s)")

        if opts["folders"]:
            if dry:
                self.stdout.write("folders: not read in a dry run")
                return
            folder_rows = LabelRecord.objects.filter(source=LabelRecord.Source.IMAP_FOLDER)
            before = folder_rows.count()
            try:
                connector.sync(unlimited=True)
            except LabelSyncIncomplete as exc:
                raise CommandError(f"LabelSyncIncomplete: {exc}") from None
            except (imap_sync.ImapLoginFailed, imap_sync.ImapTlsFailed, imap_sync.ImapConnectionLost,
                    ProviderUnavailable) as exc:
                raise CommandError(type(exc).__name__) from None
            self.stdout.write(f"folders synced: {folder_rows.count() - before} folder row(s) created")

    @staticmethod
    def _rematch(dry: bool) -> int:
        """Set the case of folder rows that matched no case when they were read, by their stored
        Message-ID (a row without one cannot be matched again). Only null to a case."""
        rows = LabelRecord.objects.filter(
            source=LabelRecord.Source.IMAP_FOLDER, case__isnull=True,
        ).exclude(message_id="").only("pk", "message_id")
        n = 0
        for row in rows.iterator(chunk_size=CHUNK):
            case = match_case(row.message_id)
            if case is None:
                continue
            if dry:
                n += 1
            else:
                n += LabelRecord.objects.filter(pk=row.pk, case__isnull=True).update(case=case)
        return n

    @staticmethod
    def _has(case, source, label_class) -> bool:
        return LabelRecord.objects.filter(
            case=case, source=source, label_class=label_class, status=LabelRecord.Status.ACTIVE,
        ).exists()
