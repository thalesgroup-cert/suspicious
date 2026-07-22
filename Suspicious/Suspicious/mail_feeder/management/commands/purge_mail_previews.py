"""
Delete objects from the `mail-previews` MinIO bucket by age and/or size.

Deliberately does not touch Mail.preview_object_key — see
mail_feeder.utils.email_preview.retention for why a deleted preview is
safe to leave "pointed at" (MailPreviewView lazily re-renders on next
view instead of erroring).

Usage:
    python manage.py purge_mail_previews --older-than-days 90
    python manage.py purge_mail_previews --min-size-mb 15
    python manage.py purge_mail_previews --older-than-days 90 --min-size-mb 15
    python manage.py purge_mail_previews --min-size-mb 15 --dry-run
"""
from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from mail_feeder.utils.email_preview.retention import purge_mail_previews


class Command(BaseCommand):
    help = "Delete mail-preview objects from MinIO by age and/or size."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--older-than-days", type=int, default=None)
        parser.add_argument("--min-size-mb", type=float, default=None)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **opts) -> None:
        older_than_days = opts["older_than_days"]
        min_size_mb = opts["min_size_mb"]
        dry_run = opts["dry_run"]

        if older_than_days is None and min_size_mb is None:
            raise CommandError(
                "Provide --older-than-days and/or --min-size-mb — refusing "
                "to run with no criteria (that would match every object)."
            )

        result = purge_mail_previews(
            older_than_days=older_than_days,
            min_size_mb=min_size_mb,
            dry_run=dry_run,
        )

        verb = "Would delete" if dry_run else "Deleted"
        self.stdout.write(self.style.SUCCESS(
            f"{verb} {result.deleted_count} object(s), "
            f"{result.deleted_bytes / (1024 * 1024):.1f} MB."
        ))
        if result.errors:
            self.stdout.write(self.style.WARNING(
                f"{len(result.errors)} object(s) failed to delete (see logs)."
            ))
