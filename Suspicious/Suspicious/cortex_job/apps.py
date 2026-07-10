from django.apps import AppConfig

class CortexConfig(AppConfig):
    name = 'cortex_job'
    
    default_auto_field = 'django.db.models.BigAutoField'
    
    verbose_name = "Cortex Job"
