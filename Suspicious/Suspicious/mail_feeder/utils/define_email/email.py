import logging
from email.utils import parseaddr
from django.core.exceptions import ValidationError
from mail_feeder.models import Mail

from .models import EmailDataModel, MailInstanceResult
from .utils import decode_subject, parse_email_date, safe_execution


logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

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
                _, addr = parseaddr(validated.reportedBy)
                decoded_subject = subject or f"Suspicious Mail by {addr or 'Unknown Sender'}"

                mail = Mail(
                    subject=decoded_subject,
                    reportedBy=addr,
                    date=parse_email_date(validated.date),
                    mail_from=validated.mail_from or "",
                    to=validated.to,
                    cc=validated.cc or "",
                    bcc=validated.bcc or "",
                    mail_id=validated.id or "",
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
