from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0007_aimodelretrainrun'),
    ]

    operations = [
        migrations.AddField(
            model_name='aimodelretrainrun',
            name='f1_score_golden',
            field=models.FloatField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name='aimodelretrainrun',
            name='accuracy_golden',
            field=models.FloatField(null=True, blank=True),
        ),
    ]
