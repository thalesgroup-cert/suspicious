from django.apps import AppConfig

class DomainConfig(AppConfig):
    name = 'domain_process'
    
    default_auto_field = 'django.db.models.BigAutoField'
    
    verbose_name = "Domain Process"
