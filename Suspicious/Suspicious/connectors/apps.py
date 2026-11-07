from django.apps import AppConfig


class ConnectorsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "connectors"

    def ready(self):
        from connectors.registry import registry
        registry.discover()
        self._register_beat_schedules()
        import connectors.signals  # noqa: F401 — registers the receiver

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
        if "ai_model" in registry.names():  # whether it is enabled is checked in the task
            entries["ai-model-retrain-check"] = {
                "task": "ai_model.tasks.maybe_start_retrain",
                "schedule": 86400.0,
            }
            entries["ai-model-server-sync"] = {
                "task": "ai_model.tasks.sync_server",
                "schedule": 300.0,
            }
        if entries:
            celery_app.conf.beat_schedule.update(entries)
