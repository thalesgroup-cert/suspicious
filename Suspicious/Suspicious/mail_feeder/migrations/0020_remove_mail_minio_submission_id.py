from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("mail_feeder", "0019_mail_reporternote"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="mail",
            name="minio_submission_id",
        ),
    ]
