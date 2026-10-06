import logging
from django.core.exceptions import ValidationError
from mail_feeder.models import Mail

from .models import EmailDataModel, MailInstanceResult
from .utils import decode_subject, parse_email_date, safe_execution


logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

def _fit(field: str, value):
    """Cut a value to the column width. A long header is attacker-controlled,
    so it must not be able to make full_clean() discard the whole mail."""
    limit = Mail._meta.get_field(field).max_length
    if value and limit and len(value) > limit:
        logger.warning("Truncating mail %s from %d to %d chars", field, len(value), limit)
        return value[: limit - 1] + "\u2026"
    return value


class EmailService:
    """
    Service responsible for validating input data and creating Mail instances.
    """

    def __init__(self):
        self.logger = logger

    def create_mail_instance(self, email_data: dict) -> MailInstanceResult:
        """
        Validate input, decode subject, and persist a Mail record.
        """
        with safe_execution("creating mail instance"):
            try:
                validated = EmailDataModel(**email_data)
                subject = decode_subject(validated.reportedSubject)
                decoded_subject = subject or f"Suspicious Mail by {validated.reportedBy}"

                mail = Mail(
                    subject=_fit("subject", decoded_subject),
                    reportedBy=_fit("reportedBy", validated.reportedBy),
                    date=parse_email_date(validated.date),
                    mail_from=_fit("mail_from", validated.mail_from or ""),
                    to=_fit("to", validated.to),
                    cc=_fit("cc", validated.cc or ""),
                    bcc=_fit("bcc", validated.bcc or ""),
                    mail_id=_fit("mail_id", validated.id or ""),
                )

                mail.full_clean()
                mail.save()
                self.logger.debug(f"Mail instance created successfully (id={mail.id})")

                return MailInstanceResult(success=True, mail_id=mail.id)

            except ValidationError as ve:
                self.logger.error(f"Validation failed: {ve}")
                return MailInstanceResult(success=False, error=str(ve))

            except Exception as e:
                self.logger.error(f"Error creating mail instance: {e}")
                return MailInstanceResult(success=False, error=str(e))
