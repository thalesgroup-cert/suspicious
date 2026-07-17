from django.db import migrations


def seed(apps, schema_editor):
    ConnectorState = apps.get_model("connectors", "ConnectorState")
    from settings.config import get_config

    def set_enabled(name, enabled):
        ConnectorState.objects.update_or_create(
            name=name, defaults={"enabled": bool(enabled)}
        )

    # Behavior-preserving defaults at upgrade time:
    set_enabled("smtp_notify", True)
    set_enabled("misp", bool(get_config("integrations.misp.instances.primary.url")))
    set_enabled("thehive", bool(get_config("integrations.thehive.url")))
    set_enabled("watcher", bool(get_config("integrations.watcher.enabled", False)))


class Migration(migrations.Migration):
    dependencies = [("connectors", "0001_initial")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
