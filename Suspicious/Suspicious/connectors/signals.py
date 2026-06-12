from django.db.models.signals import post_save
from django.dispatch import receiver

from case_handler.models import Case
from connectors.dispatch import emit


@receiver(post_save, sender=Case, dispatch_uid="connectors_case_created")
def _on_case_created(sender, instance, created, **kwargs):
    if created:
        emit("case_created", instance)
