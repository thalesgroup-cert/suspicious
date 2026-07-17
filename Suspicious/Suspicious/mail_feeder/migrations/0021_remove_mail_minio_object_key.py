from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("mail_feeder", "0020_remove_mail_minio_submission_id"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="mail",
            name="minio_object_key",
        ),
    ]
