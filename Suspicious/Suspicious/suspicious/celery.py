import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "suspicious.settings")

app = Celery("suspicious")
app.config_from_object("django.conf:settings", namespace="CELERY")

app.conf.task_time_limit = 600
app.conf.task_soft_time_limit = 540

app.autodiscover_tasks()
