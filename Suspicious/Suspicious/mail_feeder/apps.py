from django.apps import AppConfig

class MailFeederConfig(AppConfig):
    name = 'mail_feeder'
    
    default_auto_field = 'django.db.models.BigAutoField'
    
    verbose_name = "Mail Feeder"
