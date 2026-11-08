import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ai_model', '0008_shadow_result'),
        ('case_handler', '0029_campaign'),
    ]

    operations = [
        migrations.CreateModel(
            name='ShadowCampaignEffect',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('effect', models.CharField(choices=[('no_check', 'No Check'), ('none', 'None'), ('would_create', 'Would Create'), ('would_join', 'Would Join')], max_length=12)),
                ('member_case_ids', models.JSONField(default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('case', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='shadow_campaign_effects', to='case_handler.case')),
                ('live_campaign', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='case_handler.campaign')),
                ('version', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='campaign_effects', to='ai_model.modelversion')),
            ],
        ),
        migrations.AddConstraint(
            model_name='shadowcampaigneffect',
            constraint=models.UniqueConstraint(fields=('case', 'version'), name='ai_model_shadow_campaign_case_version'),
        ),
    ]
