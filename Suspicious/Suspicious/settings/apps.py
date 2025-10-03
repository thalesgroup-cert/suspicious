from django.apps import AppConfig

class SettingsConfig(AppConfig):
    # The name of the application, used for importing modules
    name = 'settings'
    
    # The default auto field to use for models in this app
    default_auto_field = 'django.db.models.BigAutoField'
    
    # A human-readable name for the application, used in the admin interface
    verbose_name = "Settings"
