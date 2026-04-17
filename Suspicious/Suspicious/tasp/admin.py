import json
import logging

import celery
from django.contrib import admin
from django_celery_results.admin import TaskResultAdmin as _BaseAdmin
from django_celery_results.models import TaskResult

admin.site.site_header = "Suspicious Administration"
admin.site.site_title = "Suspicious Admin Portal"
admin.site.index_title = "Welcome to Suspicious Admin Portal"

logger = logging.getLogger(__name__)

_Base = _BaseAdmin if isinstance(_BaseAdmin, type) else object


class TaskResultAdmin(_Base):
    actions = ["requeue_failed"]

    def requeue_failed(self, request, queryset):
        requeued = 0
        for result in queryset.filter(status="FAILURE"):
            try:
                args = json.loads(result.task_args or "[]")
                kwargs = json.loads(result.task_kwargs or "{}")
                celery.current_app.send_task(result.task_name, args=args, kwargs=kwargs)
                requeued += 1
            except Exception as exc:
                logger.warning("Failed to requeue task %s: %s", result.task_name, exc)
        self.message_user(request, f"Requeued {requeued} task(s).")

    requeue_failed.short_description = "Requeue selected failed tasks"


admin.site.register(TaskResult, TaskResultAdmin)

