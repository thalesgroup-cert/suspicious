from django.apps import AppConfig

class SubmissionQueueConfig(AppConfig):
    name = 'submission_queue'
    
    default_auto_field = 'django.db.models.BigAutoField'
    
    verbose_name = "Submission Queue"
