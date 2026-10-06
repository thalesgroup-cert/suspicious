from django.db import migrations

from cortex_job.migrations._tier_seed import tier_for


def seed_tiers(apps, schema_editor):
    Analyzer = apps.get_model("cortex_job", "Analyzer")
    for a in Analyzer.objects.all():
        new_tier = tier_for(a.name)
        if a.tier != new_tier:
            a.tier = new_tier
            a.save(update_fields=["tier"])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [("cortex_job", "0011_analyzer_tier")]
    operations = [migrations.RunPython(seed_tiers, noop)]
