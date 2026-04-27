from django.apps import AppConfig


class CaseConfig(AppConfig):
    name = 'case_handler'
    default_auto_field = 'django.db.models.BigAutoField'
    verbose_name = "Case Handler"

    def ready(self):
        import case_handler.signals  # noqa: F401
