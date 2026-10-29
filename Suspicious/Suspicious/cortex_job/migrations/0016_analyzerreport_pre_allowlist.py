from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cortex_job", "0015_analyzerreport_screenshot"),
    ]

    operations = [
        migrations.AddField(
            model_name="analyzerreport",
            name="pre_allowlist",
            field=models.JSONField(blank=True, default=None, null=True),
        ),
    ]
