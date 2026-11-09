import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ai_model', '0009_shadow_campaign'),
    ]

    operations = [
        migrations.CreateModel(
            name='ModelVersionStats',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('day', models.DateField()),
                ('scored', models.PositiveIntegerField(default=0)),
                ('dangerous', models.PositiveIntegerField(default=0)),
                ('campaign_checks', models.PositiveIntegerField(default=0)),
                ('created', models.PositiveIntegerField(default=0)),
                ('joined', models.PositiveIntegerField(default=0)),
                ('alerts', models.PositiveIntegerField(default=0)),
                ('version', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='stats', to='ai_model.modelversion')),
            ],
        ),
        migrations.AddConstraint(
            model_name='modelversionstats',
            constraint=models.UniqueConstraint(fields=('version', 'day'), name='ai_model_stats_version_day'),
        ),
    ]
