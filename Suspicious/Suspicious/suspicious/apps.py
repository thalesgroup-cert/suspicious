from django.apps import AppConfig


class SuspiciousConfig(AppConfig):
    name = "suspicious"
    verbose_name = "Suspicious Platform"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from django.conf import settings
        from suspicious.otel import configure

        configure(
            service_name=settings.OTEL_SERVICE_NAME,
            otlp_endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT,
            enabled=settings.OTEL_ENABLED,
        )
