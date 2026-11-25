from django.db import migrations, models


def mark_provider_rows(apps, schema_editor):
    from django.db.models import Q

    analyzer = apps.get_model("cortex_job", "Analyzer")
    try:
        from cortex_job.cortex_utils.cortex_and_job_management import ai_analyzer_name
        ai_name = ai_analyzer_name()
    except Exception:  # config unreadable at migrate time: fall back to the prefix alone
        ai_name = None
    match = Q(analyzer_cortex_id__startswith="provider:")
    if ai_name:
        match |= Q(name=ai_name)
    analyzer.objects.filter(match).update(source="ai_model")


class Migration(migrations.Migration):

    dependencies = [
        ("cortex_job", "0016_analyzerreport_pre_allowlist"),
    ]

    operations = [
        migrations.AddField(
            model_name="analyzer",
            name="source",
            field=models.CharField(
                db_index=True, default="cortex", max_length=100,
                help_text="Name of the connector that owns this analyzer.",
            ),
        ),
        migrations.RunPython(mark_provider_rows, migrations.RunPython.noop),
    ]
