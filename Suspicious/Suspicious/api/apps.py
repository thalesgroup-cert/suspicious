from django.apps import AppConfig


class ApiConfig(AppConfig):
    name = 'api'
    default_auto_field = 'django.db.models.BigAutoField'
    verbose_name = "API"

    def ready(self):
        from prometheus_client import REGISTRY
        from api.metrics import QUEUE_COLLECTOR
        try:
            REGISTRY.register(QUEUE_COLLECTOR)
        except Exception:
            pass  # already registered on worker reload
