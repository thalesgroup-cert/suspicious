from django.db.models.signals import post_save
from django.dispatch import receiver


@receiver(post_save, sender="case_handler.Case")
def on_case_created(sender, instance, created, **kwargs):
    if created:
        from api.metrics import cases_created_total
        cases_created_total.inc()
