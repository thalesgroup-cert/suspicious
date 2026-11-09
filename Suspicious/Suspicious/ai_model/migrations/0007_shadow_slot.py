from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ai_model', '0006_retrain_job_excluded_rows'),
    ]

    operations = [
        migrations.AddField(
            model_name='modelversion',
            name='shadow_slot',
            field=models.PositiveSmallIntegerField(editable=False, null=True, unique=True),
        ),
        migrations.AddField(
            model_name='modelversion',
            name='shadow_since',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='modelversion',
            name='shadow_min_days',
            field=models.PositiveSmallIntegerField(default=7),
        ),
        migrations.AddField(
            model_name='modelversion',
            name='recheck',
            field=models.JSONField(default=dict),
        ),
        migrations.AddConstraint(
            model_name='modelversion',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('shadow_slot', 1), ('shadow_slot__isnull', False), ('status', 'shadow')), models.Q(models.Q(('status', 'shadow'), _negated=True), ('shadow_slot__isnull', True)), _connector='OR'), name='ai_model_shadow_slot_matches_status'),
        ),
    ]
