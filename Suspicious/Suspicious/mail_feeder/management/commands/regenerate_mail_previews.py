"""
Regenerate Mail.preview_png PNGs for rows that still point at the legacy
collision-prone path "mail_previews/preview.png".

Background: previously every preview was saved under the literal filename
"preview.png", which collided on MinIO (no get_available_name() rename).
Commit f295d39 fixed the writer to use "preview_<mail.pk>.png" per row,
but historical rows still reference the dead shared blob. This command
re-fetches each Mail's archived .eml from MinIO and re-renders the PNG
with the new pk-scoped filename, so the UI can stop returning 404 for
those cases.

Usage:
    python manage.py regenerate_mail_previews              # stale rows only
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

LEGACY_PREVIEW_NAME = "mail_previews/preview.png"


class Command(BaseCommand):
    help = "Regenerate Mail.preview_png entries that point at the legacy shared path."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--all",
            action="store_true",
            help="Regenerate every Mail with a populated preview_png, "
                 "not just rows pointing at the legacy shared blob.",
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

        qs = Mail.objects.exclude(preview_png="").exclude(preview_png__isnull=True)
        if not regenerate_all:
            qs = qs.filter(preview_png=LEGACY_PREVIEW_NAME)
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
            f"{'all' if regenerate_all else 'legacy only'})."
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
        self.stdout.write(self.style.SUCCESS(
            f"  mail#{mail.pk}: regenerated -> {mail.preview_png.name}"
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

        # Prefer any .eml that is NOT the reporter wrapper.
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
