from django.apps import AppConfig

class FileConfig(AppConfig):
    name = 'file_process'
    
    default_auto_field = 'django.db.models.BigAutoField'
    
    verbose_name = "File Process"
