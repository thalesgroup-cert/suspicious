from django.apps import AppConfig

class SettingsConfig(AppConfig):
    name = 'settings'
    
    default_auto_field = 'django.db.models.BigAutoField'
    
    verbose_name = "Settings"
