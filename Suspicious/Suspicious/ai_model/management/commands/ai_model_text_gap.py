"""ai_model_text_gap: how far the live mail text (what the classifier sees at inference) is from the
text of the same mail filed in a review folder (what the ledger embeddings came from), as cosine
similarity of their "classifier" embeddings (Plan E, Task 1, Ruling E3).

Read-only: no ledger or database writes, the mailbox is opened read-only. Prints counts and
statistics only: never mail text, subjects, addresses, usernames or case ids."""
import math
import statistics

from django.core.management.base import BaseCommand, CommandError

from ai_model import ledger
from ai_model.models import LabelRecord
from connectors.contrib.ai_model import imap_sync
from connectors.contrib.ai_model.mailtext import mail_archive_for, read_archive_body
from connectors.providers import ProviderUnavailable

BATCH = 32


def cosine(a, b) -> float:
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(x * x for x in b))
    return sum(x * y for x, y in zip(a, b)) / (na * nb) if na and nb else 0.0


def percentile(values, q) -> float:
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo = int(pos)
    return ordered[lo] + (ordered[min(lo + 1, len(ordered) - 1)] - ordered[lo]) * (pos - lo)


def _locator(source_ref):
    """(folder, uidvalidity, uid) from "folder:uidvalidity:uid"; None when it does not parse."""
    folder, _, tail = source_ref.rpartition(":")
    folder, _, validity = folder.rpartition(":")
    try:
        return (folder, int(validity), int(tail)) if folder else None
    except ValueError:
        return None


class Command(BaseCommand):
    help = "Report the cosine similarity between the live and the filed text of labelled mails. Read-only."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=200, help="most folder rows to examine")

    def handle(self, *args, **opts):
        from connectors.registry import registry
        if not ledger.enabled():
            raise CommandError("the ai_model connector is disabled")
        connector = registry.instantiate("ai_model")
        config = connector.config
        if not config.get("imap_host"):
            raise CommandError("no imap_host configured for the ai_model connector")

        skipped = {"no archive": 0, "no IMAP row": 0, "UIDVALIDITY mismatch": 0, "fetch failed": 0}
        pairs = []  # (label_class, live text, filed text)
        rows = (LabelRecord.objects.filter(source=LabelRecord.Source.IMAP_FOLDER, case__isnull=False)
                .exclude(status=LabelRecord.Status.SUPERSEDED).select_related("case").order_by("-pk")
                [:max(opts["limit"], 0)])
        imap = None
        try:
            for row in rows:
                try:
                    live = read_archive_body(mail_archive_for(row.case))
                except ProviderUnavailable:
                    live = None
                if not live:
                    skipped["no archive"] += 1
                    continue
                where = _locator(row.source_ref)
                if where is None:
                    skipped["no IMAP row"] += 1
                    continue
                if imap is None:
                    imap = imap_sync.connect(
                        config.get("imap_host"), int(config.get("imap_port") or 993),
                        config.get("imap_user") or "", config.get("imap_password") or "",
                        config.get("imap_use_ssl", True) is not False)
                try:
                    mail = imap_sync.fetch_one(imap, *where)
                except imap_sync.UidValidityChanged:
                    skipped["UIDVALIDITY mismatch"] += 1
                    continue
                except imap_sync.FolderUnavailable:
                    mail = None
                if mail is None or not mail.text:
                    skipped["fetch failed"] += 1
                    continue
                pairs.append((row.label_class, live, mail.text))
            sims = self._similarities(connector, pairs)
        except (imap_sync.ImapConnectionLost, imap_sync.ImapLoginFailed, imap_sync.ImapTlsFailed,
                ProviderUnavailable, ValueError) as exc:
            raise CommandError(type(exc).__name__) from None
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:  # noqa: BLE001 -- closing only
                    pass

        out = self.stdout.write
        out(f"compared: {len(sims)}")
        out("skipped: " + ", ".join(f"{k} {v}" for k, v in skipped.items()))
        if sims:
            values = [s for _, s in sims]
            out(f"cosine median {statistics.median(values):.4f} p5 {percentile(values, 0.05):.4f} "
                f"p95 {percentile(values, 0.95):.4f}")
            for label_class in sorted({c for c, _ in sims}):
                out(f"  {label_class}: median {statistics.median(s for c, s in sims if c == label_class):.4f}")

    def _similarities(self, connector, pairs):
        client = connector._client()
        sims = []
        for i in range(0, len(pairs), BATCH):
            chunk = pairs[i:i + BATCH]
            texts = [t for _, live, filed in chunk for t in (live, filed)]
            vectors = client.embed(texts, "classifier")["vectors"]
            if len(vectors) != len(texts):
                raise ValueError("embed answer size")
            sims += [(c, cosine(vectors[2 * n], vectors[2 * n + 1])) for n, (c, _, _) in enumerate(chunk)]
        return sims
