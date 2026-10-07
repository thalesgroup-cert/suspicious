"""Helpers for destructive migrations."""
from django.db import migrations


def refuse_if_rows(app_label: str, model_name: str) -> migrations.RunPython:
    """RunPython step that aborts the migration if the model still has rows, so a
    DeleteModel can never silently drop data. Reverse is a no-op."""

    def forward(apps, schema_editor):
        model = apps.get_model(app_label, model_name)
        count = model.objects.using(schema_editor.connection.alias).count()
        if count:
            raise RuntimeError(
                f"Refusing to drop {app_label}.{model_name}: {count} row(s) present. "
                "Export or migrate them, delete the rows, then re-run the migration."
            )

    return migrations.RunPython(forward, migrations.RunPython.noop)
