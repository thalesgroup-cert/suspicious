from django.apps import AppConfig


class ConnectorsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "connectors"

    def ready(self):
        from connectors.registry import registry
        registry.discover()
        self._register_beat_schedules()
        import connectors.signals  # noqa: F401 — registers the receiver

        # Best-of-both-worlds: let operators set connector secrets in
        # settings.json and migrate them into Vault on boot (seed-if-missing).
        from connectors.bootstrap import seed_connector_secrets_from_settings
        seed_connector_secrets_from_settings()

    @staticmethod
    def _register_beat_schedules():
        """Add one beat entry per manifest schedule. Runs in every process
        that loads Django (web, worker, beat) — only beat consumes it."""
        from connectors.registry import registry
        from suspicious.celery import app as celery_app

        entries = {
            f"connector-{name}-{schedule.name}": {
                "task": "connectors.tasks.run_connector_sync",
                "schedule": float(schedule.interval_seconds),
                "args": [name],
            }
            for name, schedule in registry.scheduled()
        }
        if entries:
            celery_app.conf.beat_schedule.update(entries)
