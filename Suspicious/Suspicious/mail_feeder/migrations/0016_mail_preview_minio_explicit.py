"""
Replace Mail.preview_png (ImageField + Django storage roulette) with two
explicit CharFields that point at the MinIO object directly.

Motivation
----------
ImageField + DualStorage left Django free to fall back to
FileSystemStorage when the primary MinIO blob was missing. The fallback
URL (`/media/mail_previews/preview.png`) is not routed by the production
urlconf, so the admin's auto-rendered <img> 404'd.

Now we own the storage mapping: `preview_bucket` + `preview_object_key`
are the canonical pointers. Reading the preview goes through
api.views.mail_preview.MailPreviewView which streams from MinIO using
the explicit (bucket, key) pair — no storage backend indirection.

Behaviour
---------
- Existing preview_png values are not migrated. The data is regenerable
  from each case's archived .eml via:
      python manage.py regenerate_mail_previews --all
  Until that command is run the UI shows "No preview" for old rows.
- preview_png is dropped to remove the abstraction entirely. Keeping it
  alongside the new fields would invite drift between the two sources
  of truth.
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("mail_feeder", "0015_remove_mailbody_mail_feeder_fuzzy_h_dfe882_idx_and_more"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="mail",
            name="preview_png",
        ),
        migrations.AddField(
            model_name="mail",
            name="preview_bucket",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="mail",
            name="preview_object_key",
            field=models.CharField(blank=True, max_length=512),
        ),
    ]
