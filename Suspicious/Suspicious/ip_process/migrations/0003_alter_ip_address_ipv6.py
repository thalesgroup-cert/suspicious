from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("ip_process", "0002_alter_ip_ioc_level_alter_ip_ioc_score"),
    ]

    operations = [
        migrations.AlterField(
            model_name="ip",
            name="address",
            field=models.CharField(max_length=45),
        ),
    ]
