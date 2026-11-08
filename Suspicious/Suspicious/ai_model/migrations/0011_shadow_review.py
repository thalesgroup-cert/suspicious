import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ai_model', '0010_version_stats'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ShadowReview',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('kind', models.CharField(choices=[('flip', 'Flip'), ('campaign', 'Campaign')], max_length=8)),
                ('case_id', models.PositiveIntegerField()),
                ('note', models.TextField(blank=True)),
                ('at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('version', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reviews', to='ai_model.modelversion')),
            ],
            options={
                'indexes': [models.Index(fields=['version', 'kind', 'case_id'], name='ai_model_review_item')],
            },
        ),
    ]
