import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "suspicious.settings")

app = Celery("suspicious")
app.config_from_object("django.conf:settings", namespace="CELERY")

# Hard kill at 10 min; SoftTimeLimitExceeded raised 1 min earlier so handlers
# can clean up. Override per-task via @shared_task(time_limit=..., soft_time_limit=...).
app.conf.task_time_limit = 600
app.conf.task_soft_time_limit = 540

app.autodiscover_tasks()
