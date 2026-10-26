from django.apps import AppConfig


class SuspiciousConfig(AppConfig):
    name = "suspicious"
    verbose_name = "Suspicious Platform"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from django.conf import settings
        from django.core.exceptions import ImproperlyConfigured

        from common.storage.checks import unknown_provider_candidates
        from common.storage.registry import known_providers

        # System checks only run under manage.py; gunicorn and Celery start without them.
        bad = unknown_provider_candidates()
        if bad:
            source, name = bad[0]
            raise ImproperlyConfigured(
                f"Unknown storage provider {name!r} (from {source}); "
                f"registered providers: {', '.join(known_providers())}."
            )

        from suspicious.otel import configure

        configure(
            service_name=settings.OTEL_SERVICE_NAME,
            otlp_endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT,
            enabled=settings.OTEL_ENABLED,
        )
