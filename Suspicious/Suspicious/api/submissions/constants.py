from django.conf import settings


DEFAULT_SUBMISSION_ELEVATED_GROUPS = ("CERT", "CISO", "Admin")

SUBMISSION_ELEVATED_GROUPS = tuple(
    getattr(settings, "SUBMISSION_ELEVATED_GROUPS", DEFAULT_SUBMISSION_ELEVATED_GROUPS)
)

SUBMISSION_STATUS_CHOICES = (
    "NEW",
    "IN_PROGRESS",
    "DONE",
    "CHALLENGED",
    "UNKNOWN",
)

SUBMISSION_RESULT_CHOICES = (
    "SAFE",
    "INCONCLUSIVE",
    "UNCHALLENGED",
    "ALLOW_LISTED",
    "FAILURE",
    "SUSPICIOUS",
    "DANGEROUS",
    "UNKNOWN",
)

SUBMISSION_TYPE_CHOICES = (
    "FILE",
    "MAIL",
    "URL",
    "IP",
    "HASH",
    "UNKNOWN",
)

ANALYZER_TARGET_KIND_CHOICES = (
    "URL",
    "DOMAIN",
    "MAIL",
    "HASH",
    "FILE",
    "IP",
    "MAIL_BODY",
    "MAIL_HEADER",
    "UNKNOWN",
)

STATUS_MAP = {
    "to do": "NEW",
    "todo": "NEW",
    "ongoing": "IN_PROGRESS",
    "on going": "IN_PROGRESS",
    "in progress": "IN_PROGRESS",
    "inprogress": "IN_PROGRESS",
    "done": "DONE",
    "challenged": "CHALLENGED",
}

RESULT_MAP = {
    "Safe": "SAFE",
    "Inconclusive": "INCONCLUSIVE",
    "Unchallenged": "UNCHALLENGED",
    "AllowListed": "ALLOW_LISTED",
    "Failure": "FAILURE",
    "Suspicious": "SUSPICIOUS",
    "Dangerous": "DANGEROUS",
}