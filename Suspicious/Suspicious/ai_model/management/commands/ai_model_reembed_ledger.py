"""ai_model_reembed_ledger: re-embed the trainable folder rows whose classifier embedding is not in
the training preprocessing (TRAINING_PREPROCESSING), so the ledger can be exported for training
(Plan E, Task 8a). Each mail is read again by its locator (source_ref folder:uidvalidity:uid, the
mailbox opened read-only) and embedded through /v2/embed in batches of 32; only `embedding` and
`preprocessing_version` change, through ledger.replace_embedding, one transaction per batch. Rows
whose mail is gone or whose folder's UIDVALIDITY changed are skipped and counted. Prints counts
only: never mail text, subjects, addresses or credentials."""
import imaplib

from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, transaction

from ai_model import ledger
from ai_model.export import trainable_rows
from ai_model.management.commands.ai_model_text_gap import _locator, imap_port, open_imap
from ai_model.training_data import TRAINING_PREPROCESSING
from connectors.contrib.ai_model import imap_sync
from connectors.providers import ProviderUnavailable

BATCH = 32  # the /v2/embed limit


class Command(BaseCommand):
    help = f"Re-embed trainable ledger rows not in {TRAINING_PREPROCESSING}."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=None, help="most rows to re-embed")
        parser.add_argument("--dry-run", action="store_true", help="count the rows, change nothing")

    def handle(self, *args, **opts):
        from connectors.registry import registry
        rows = (trainable_rows().exclude(preprocessing_version=TRAINING_PREPROCESSING).order_by("pk")
                .only("pk", "source_ref", "preprocessing_version"))  # not the vectors
        if opts["limit"] is not None:
            rows = rows[:max(opts["limit"], 0)]
        if opts["dry_run"]:
            self.stdout.write(f"to re-embed: {rows.count()}")
            return
        if not ledger.enabled():
            raise CommandError("the ai_model connector is disabled")
        connector = registry.instantiate("ai_model")
        config = connector.config
        if not config.get("imap_host"):
            raise CommandError("no imap_host configured for the ai_model connector")
        port = imap_port(config)
        self.done = 0
        self.skipped = {"gone": 0, "UIDVALIDITY changed": 0, "bad locator": 0, "changed meanwhile": 0}
        imap = None
        try:
            client = connector._client()
            pending = []  # (row, text)
            for row in rows:
                where = _locator(row.source_ref)
                if where is None:
                    self.skipped["bad locator"] += 1
                    continue
                if imap is None:
                    imap = open_imap(config, port)
                try:
                    mail = imap_sync.fetch_one(imap, *where)
                except imap_sync.UidValidityChanged:
                    self.skipped["UIDVALIDITY changed"] += 1
                    continue
                except imap_sync.FolderUnavailable:
                    mail = None
                if mail is None or not mail.text:
                    self.skipped["gone"] += 1
                    continue
                pending.append((row, mail.text))
                if len(pending) == BATCH:
                    self._write(client, pending)
                    pending = []
            if pending:
                self._write(client, pending)
        except (imap_sync.ImapConnectionLost, imap_sync.ImapLoginFailed, imap_sync.ImapTlsFailed,
                ProviderUnavailable, ValueError, OSError, imaplib.IMAP4.error, DatabaseError) as exc:
            raise CommandError(type(exc).__name__) from None
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:  # noqa: BLE001 -- closing only
                    pass
        self.stdout.write(f"re-embedded: {self.done}")
        self.stdout.write("skipped: " + ", ".join(f"{k} {v}" for k, v in self.skipped.items()))

    def _write(self, client, pending):
        answer = client.embed([t for _, t in pending], "classifier", preprocessing=TRAINING_PREPROCESSING)
        if answer["preprocessing_version"] != TRAINING_PREPROCESSING:
            # an inference server without the preprocessing field answers legacy-first128
            raise CommandError(f"the inference server embedded in {str(answer['preprocessing_version'])[:32]!a}, "
                               f"expected {TRAINING_PREPROCESSING}: update the ai_inference image")
        if len(answer["vectors"]) != len(pending):
            raise ValueError("embed answer size")
        with transaction.atomic():
            for (row, _), vector in zip(pending, answer["vectors"]):
                if ledger.replace_embedding(row, vector, TRAINING_PREPROCESSING):
                    self.done += 1
                else:
                    self.skipped["changed meanwhile"] += 1
