from kombu.exceptions import OperationalError
from rest_framework.response import Response
from rest_framework.views import exception_handler


def broker_aware_exception_handler(exc, context):
    """A dead Celery broker is a transient outage, not a server bug: 503 + Retry-After
    lets automations back off instead of treating the submission as rejected."""
    if isinstance(exc, OperationalError):
        return Response(
            {"status": "error", "code": "broker_unavailable",
             "detail": "Analysis queue unavailable, retry shortly."},
            status=503, headers={"Retry-After": "30"},
        )
    return exception_handler(exc, context)
