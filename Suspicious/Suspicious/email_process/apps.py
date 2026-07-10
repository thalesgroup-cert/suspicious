from django.apps import AppConfig

class EmailConfig(AppConfig):
    name = 'email_process'
    
    default_auto_field = 'django.db.models.BigAutoField'
    
    verbose_name = "Email Process"
