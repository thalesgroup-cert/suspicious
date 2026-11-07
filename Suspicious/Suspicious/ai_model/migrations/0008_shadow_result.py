import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ai_model', '0007_shadow_slot'),
        ('case_handler', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ShadowResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('origin', models.CharField(choices=[('live', 'Live'), ('seed', 'Seed')], default='live', max_length=4)),
                ('result', models.CharField(choices=[('SAFE', 'Safe'), ('UNWANTED', 'Unwanted'), ('DANGEROUS', 'Dangerous'), ('INCONCLUSIVE', 'Inconclusive')], max_length=20)),
                ('sub_class', models.CharField(blank=True, max_length=32)),
                ('score', models.FloatField()),
                ('confidence', models.FloatField()),
                ('probabilities', models.JSONField(default=dict)),
                ('tier', models.CharField(blank=True, max_length=8)),
                ('error', models.CharField(blank=True, max_length=64)),
                ('live_result', models.CharField(blank=True, max_length=20)),
                ('would_be_result', models.CharField(blank=True, max_length=20)),
                ('would_be_score', models.FloatField(blank=True, null=True)),
                ('would_be_confidence', models.FloatField(blank=True, null=True)),
                ('would_be_rule', models.CharField(blank=True, max_length=64)),
                ('flip', models.CharField(choices=[('none', 'None'), ('changed', 'Changed'), ('critical', 'Critical')], default='none', max_length=8)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('case', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='shadow_results', to='case_handler.case')),
                ('version', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='shadow_results', to='ai_model.modelversion')),
            ],
        ),
        migrations.AddConstraint(
            model_name='shadowresult',
            constraint=models.UniqueConstraint(fields=('case', 'version'), name='ai_model_shadow_result_case_version'),
        ),
    ]
