from django.db import migrations


def restore_tmp_path_prefix(apps, schema_editor):
    """File.tmp_path used to be stored with its "/tmp/" prefix stripped for
    uploaded files (mail-archive tmp_paths were always absolute already -
    see file_handler.py's old `mail` branch). get_data_value used to
    reconstruct that prefix at read time; it no longer does, so rows written
    before this migration need their prefix restored once, up front."""
    File = apps.get_model("file_process", "File")
    for file_instance in File.objects.exclude(tmp_path="").exclude(tmp_path__startswith="/"):
        if "tar.gz" in file_instance.tmp_path:
            continue
        file_instance.tmp_path = f"/tmp/{file_instance.tmp_path}"
        file_instance.save(update_fields=["tmp_path"])


class Migration(migrations.Migration):

    dependencies = [
        ("file_process", "0002_alter_file_file_level_alter_file_file_score"),
    ]

    operations = [
        migrations.RunPython(restore_tmp_path_prefix, migrations.RunPython.noop),
    ]
