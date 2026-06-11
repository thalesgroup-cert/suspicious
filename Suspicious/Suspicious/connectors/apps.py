from django.apps import AppConfig


class ConnectorsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "connectors"

    def ready(self):
        from connectors.registry import registry
        registry.discover()
