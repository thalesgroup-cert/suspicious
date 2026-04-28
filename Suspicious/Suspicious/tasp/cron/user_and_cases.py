import logging
from django.contrib.auth.models import User
from case_handler.models import Case
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
from profiles.profiles_utils.ldap import Ldap

logger = logging.getLogger("cron.users_cases")
log_cases = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def sync_user_profiles() -> None:
    """Synchronise les profils utilisateurs via LDAP."""
    for user in User.objects.all():
        try:
            Ldap.create_user(user)
        except Exception:
            logger.exception("Failed to sync user %s", user.pk)


def update_ongoing_case_jobs() -> None:
    """Mise à jour des jobs Cortex pour les cases en cours."""
    from opentelemetry import trace

    tracer = trace.get_tracer(__name__)
    cases = Case.objects.filter(status="On Going")
    if not cases:
        log_cases.info("No ongoing cases found.")
        return

    with tracer.start_as_current_span("cron.update_ongoing_case_jobs") as span:
        span.set_attribute("cases.count", len(cases))
        manager = CortexJobManager()
        for case in cases:
            try:
                with tracer.start_as_current_span("cron.manage_case_jobs") as case_span:
                    case_span.set_attribute("case.id", case.id)
                    manager.manage_jobs(case)
                    case.save()
            except Exception:
                log_cases.exception(
                    "Case %s update failed", getattr(case, "id", "<unknown>")
                )
