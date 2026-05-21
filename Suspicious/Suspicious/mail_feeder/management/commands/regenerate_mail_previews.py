"""
Regenerate Mail preview PNGs for rows that have no
`preview_object_key` set (or for every row when `--all` is passed).

After migration 0016 the preview is stored as an explicit (bucket, key)
pair on the Mail row instead of via Django's ImageField + DEFAULT_FILE_STORAGE.
Historical rows therefore have empty pointers; this command re-fetches each
Mail's archived .eml from MinIO and re-runs Eml2PngRenderer, which uploads
the PNG directly to the `mail-previews` bucket and updates the row.

Usage:
    python manage.py regenerate_mail_previews              # missing only
    python manage.py regenerate_mail_previews --all        # every row
    python manage.py regenerate_mail_previews --limit 50   # cap iterations
    python manage.py regenerate_mail_previews --dry-run    # show plan only

Each row is processed inside its own try/except so a single broken
archive can't abort the whole run; per-mail outcomes are logged.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from django.core.management.base import BaseCommand, CommandError

from mail_feeder.models import Mail, MailArchive
from mail_feeder.utils.email_preview.eml2png_renderer import Eml2PngRenderer
from mail_feeder.utils.email_preview.preview_jobs import (
    fetch_eml_bytes,
    regenerate_mail_preview,
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Regenerate Mail previews that are missing or stale, uploading to the mail-previews MinIO bucket."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--all",
            action="store_true",
            help="Regenerate every Mail, not just rows whose preview_object_key is empty.",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help="Stop after processing this many rows.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Log what would be regenerated without writing.",
        )

    def handle(self, *args, **opts) -> None:
        regenerate_all: bool = opts["all"]
        limit: Optional[int] = opts["limit"]
        dry_run: bool = opts["dry_run"]

        qs = Mail.objects.all()
        if not regenerate_all:
            qs = qs.filter(preview_object_key="")
        qs = qs.order_by("pk")
        if limit:
            qs = qs[:limit]

        total = qs.count()
        if total == 0:
            self.stdout.write(self.style.SUCCESS("Nothing to regenerate."))
            return

        self.stdout.write(
            f"Regenerating {total} preview(s) "
            f"({'dry-run' if dry_run else 'live'}, "
            f"{'all' if regenerate_all else 'missing only'})."
        )

        renderer = Eml2PngRenderer()
        storage = None
        if not dry_run:
            storage = self._get_storage_client()

        ok = skipped = failed = 0
        for mail in qs.iterator(chunk_size=50):
            outcome = self._process_one(
                mail=mail, renderer=renderer, storage=storage, dry_run=dry_run,
            )
            if outcome == "ok":
                ok += 1
            elif outcome == "skipped":
                skipped += 1
            else:
                failed += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Done. regenerated={ok} skipped={skipped} failed={failed}"
            )
        )

    # ------------------------------------------------------------------
    # Per-row work
    # ------------------------------------------------------------------

    def _process_one(self, *, mail: Mail, renderer: Eml2PngRenderer, storage, dry_run: bool) -> str:
        archive = MailArchive.objects.filter(mail=mail).first()
        if archive is None or not archive.bucket_name:
            self.stdout.write(f"  mail#{mail.pk}: no fetchable MailArchive — skipped")
            return "skipped"

        if dry_run:
            self.stdout.write(
                f"  mail#{mail.pk}: would re-render from bucket={archive.bucket_name}"
            )
            return "ok"

        # Delegate to the shared helper that also backs the Celery tasks,
        # so the command and the worker render previews identically.
        outcome = regenerate_mail_preview(
            mail,
            fetch_eml=lambda a: fetch_eml_bytes(storage, a.bucket_name),
            renderer=renderer,
        )

        if outcome == "ok":
            self.stdout.write(self.style.SUCCESS(
                f"  mail#{mail.pk}: regenerated -> {mail.preview_bucket}/{mail.preview_object_key}"
            ))
        elif outcome == "skipped":
            self.stdout.write(f"  mail#{mail.pk}: no .eml in bucket — skipped")
        else:
            self.stdout.write(self.style.WARNING(
                f"  mail#{mail.pk}: render failed (see logs)"
            ))
        return outcome

    # ------------------------------------------------------------------
    # MinIO helpers — reuse the same loader the downloads view uses so
    # the command works in any deployment without extra wiring.
    # ------------------------------------------------------------------

    def _get_storage_client(self):
        from api.views.downloads import load_minio_config
        from api.storage import StorageClient

        config_path = os.environ.get("SUSPICIOUS_CONFIG_PATH", "/app/settings.json")
        cfg = load_minio_config(config_path)
        if not cfg:
            raise CommandError(
                f"Could not load MinIO config from {config_path}"
            )
        storage = StorageClient(cfg)
        if not getattr(storage, "client", None):
            raise CommandError("MinIO client initialisation failed")
        return storage
