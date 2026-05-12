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
import tempfile
from pathlib import Path
from typing import Optional

from django.core.management.base import BaseCommand, CommandError

from mail_feeder.models import Mail, MailArchive
from mail_feeder.utils.email_preview.eml2png_renderer import Eml2PngRenderer

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
            self.stdout.write(f"  mail#{mail.pk}: no MailArchive — skipped")
            return "skipped"

        if dry_run:
            self.stdout.write(
                f"  mail#{mail.pk}: would re-render from bucket={archive.bucket_name}"
            )
            return "ok"

        try:
            eml_bytes = self._fetch_eml_bytes(storage, archive.bucket_name)
        except Exception as exc:
            logger.warning(
                "regenerate_mail_previews: mail#%s fetch failed bucket=%s err=%s",
                mail.pk, archive.bucket_name, exc,
            )
            self.stdout.write(self.style.WARNING(
                f"  mail#{mail.pk}: fetch failed ({exc}) — failed"
            ))
            return "failed"

        if not eml_bytes:
            self.stdout.write(f"  mail#{mail.pk}: no .eml in bucket — skipped")
            return "skipped"

        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as fp:
            fp.write(eml_bytes)
            tmp_path = Path(fp.name)

        try:
            png_bytes = renderer.render_eml_path_to_png_bytes(tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        if not png_bytes:
            self.stdout.write(self.style.WARNING(
                f"  mail#{mail.pk}: renderer returned no bytes — failed"
            ))
            return "failed"

        renderer.save_preview_to_mail(mail, png_bytes)

        if not mail.preview_object_key:
            self.stdout.write(self.style.WARNING(
                f"  mail#{mail.pk}: upload did not persist key — failed"
            ))
            return "failed"

        self.stdout.write(self.style.SUCCESS(
            f"  mail#{mail.pk}: regenerated -> {mail.preview_bucket}/{mail.preview_object_key}"
        ))
        return "ok"

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

    @staticmethod
    def _fetch_eml_bytes(storage, bucket_name: str) -> Optional[bytes]:
        """Stream the previewable .eml from the bucket.

        Buckets typically contain both the reporter wrapper
        (`user_submission.eml`) and the actual reported message (any
        other .eml). The preview must always render the reported
        message, never the wrapper. We pick the first non-wrapper .eml
        and only fall back to user_submission.eml when nothing else
        exists (e.g. legacy submissions before the split).
        """
        objects = list(storage.client.list_objects(bucket_name, recursive=True))
        eml_keys = [
            getattr(o, "object_name", "") or "" for o in objects
            if (getattr(o, "object_name", "") or "").lower().endswith(".eml")
        ]
        if not eml_keys:
            return None

        non_wrapper = [
            k for k in eml_keys
            if not k.lower().endswith("user_submission.eml")
        ]
        eml_key = non_wrapper[0] if non_wrapper else eml_keys[0]

        response = None
        try:
            response = storage.client.get_object(bucket_name, eml_key)
            return response.read()
        finally:
            if response is not None:
                try:
                    response.close()
                    response.release_conn()
                except Exception:
                    pass
