from django.apps import AppConfig

class DashboardConfig(AppConfig):
    name = 'dashboard'
    
    default_auto_field = 'django.db.models.BigAutoField'
    
    verbose_name = "Dashboard"
