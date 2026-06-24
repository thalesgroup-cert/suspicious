import enum


class MailTag(enum.StrEnum):
    TODO = "To Do"
    STATUS = "Status"


class SubmissionOutcome(enum.StrEnum):
    """Result of classifying a fetched inbox submission."""

    VALID = "valid"
    """Submission carries an attached mail -> extract + upload to S3."""

    NO_ATTACHED_MAIL = "no_attached_mail"
    """Submission has no attached mail -> acknowledge bad mail, store nothing."""
