from django.db import migrations
from django.db.models import F


def backfill(apps, schema_editor):
    """confidence_ai was written as analyzer.confidence * 10 (cortex_and_job_management.py:838),
    double-scaling a value that was already 0-100 — e.g. 99% got stored as 990.
    confidence_ai has exactly one writer in the codebase, so every existing
    row needs the same /10 correction."""
    Case = apps.get_model("case_handler", "Case")
    Case.objects.exclude(confidence_ai=0).update(confidence_ai=F("confidence_ai") / 10)


class Migration(migrations.Migration):
    dependencies = [
        ("case_handler", "0022_case_thehive_alert_id"),
    ]
    operations = [migrations.RunPython(backfill, migrations.RunPython.noop)]
