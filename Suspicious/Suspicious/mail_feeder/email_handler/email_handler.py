import logging
from typing import List, Tuple, Optional
from mail_feeder.models import Mail
from mail_feeder.utils.define_email.email import EmailService
from mail_feeder.utils.email_observables.services import EmailObservablesService
from mail_feeder.utils.process_em_body.email_body import EmailBodyService
from mail_feeder.utils.process_em_header.email_header import EmailHeaderService
from .models import EmailDataModel
from .utils import safe_operation, increment_field

fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


class EmailHandlerService:
    """
    Service-oriented handler for processing, validating, and updating email objects.
    """

    def __init__(self):
        self.email_service = EmailService()
        self.body_service = EmailBodyService()
        self.header_service = EmailHeaderService()
        self.observables_service = EmailObservablesService()

    def handle_mail(self, email_data: dict, workdir: str) -> Optional[Mail]:
        """
        Handles a single email by validating, determining type, and processing it.
        """
        fetch_mail_logger.debug(email_data)
        data = email_data
        email_list, email_body_list, email_header_list = self._check_existing_data(data)

        if not any([email_list, email_body_list, email_header_list]):
            fetch_mail_logger.debug("Handling new mail")
            return self._handle_new_mail(data, workdir)

        fetch_mail_logger.debug("Handling existing mail")
        return self._handle_existing_mail(data, email_list, email_body_list, email_header_list, workdir)

    def _handle_new_mail(self, data: EmailDataModel, workdir: str) -> Optional[Mail]:
        with safe_operation("handle_new_mail"):
            fetch_mail_logger.debug("Creating new mail instance")
            try:
                mail_instance_result = self.email_service.create_mail_instance(data.dict())
            except Exception as e:
                fetch_mail_logger.error(f"Mail instance creation failed: {e}")
                return None

            if not mail_instance_result or not mail_instance_result.success:
                fetch_mail_logger.warning("Mail instance creation unsuccessful")
                return None

            try:
                mail_instance = Mail.objects.get(id=mail_instance_result.mail_id)
            except Mail.DoesNotExist:
                fetch_mail_logger.error(
                    f"Mail instance not found with ID: {mail_instance_result.mail_id}"
                )
                return None

            mail_instance = self._save_and_update_mail(mail_instance, data)
            self._process_rich_observables(mail_instance, data, workdir)
            self._update_times_sent(mail_instance)
            self._save_mail(mail_instance)
            return mail_instance

    def _handle_existing_mail(
        self,
        data: EmailDataModel,
        email_list: List[Mail],
        email_body_list: list,
        email_header_list: list,
        workdir: str,
    ) -> Optional[Mail]:
        with safe_operation("handle_existing_mail"):
            if email_list:
                mail_instance = email_list[0]
                mail_instance = self._update_existing_mail(
                    mail_instance, data, email_body_list, email_header_list
                )
                fetch_mail_logger.debug(f"Updated existing mail: {mail_instance.mail_id}")
                self._update_times_sent(mail_instance)
                self._save_mail(mail_instance)
                return mail_instance

        return self._handle_new_mail(data, workdir)

    def _check_existing_data(self, data: EmailDataModel) -> Tuple[List[Mail], list, list]:
        email_list = list(Mail.objects.filter(mail_id=str(data.id)))
        email_body_list = self.body_service.check_email_bodies(data.reportedText) if data.reportedText else []
        email_header_list = self.header_service.check_email_headers(data.headers) if data.headers else []
        return email_list, email_body_list, email_header_list

    def _save_and_update_mail(self, mail_instance: Mail, data: EmailDataModel) -> Mail:
        """
        Saves the base Mail instance and attaches body and header.
        """
        mail_instance = self._save_mail(mail_instance)

        body = self.body_service.create_mail_body_instance(data.reportedText)
        if body:
            self.body_service.save_mail_body_instance(body)
            mail_instance.mail_body = body

        header = self.header_service.create_mail_header_instance(str(data.headers))
        if header:
            self.header_service.save_mail_header_instance(header)
            mail_instance.mail_header = header

        return self._save_mail(mail_instance)

    def _update_existing_mail(
        self, mail_instance: Mail, data: EmailDataModel, body_list: list, header_list: list
    ) -> Mail:
        """
        Updates an existing mail instance with new body/header data.
        """
        
        if body_list:
            fetch_mail_logger.error("Existing mail body found, updating times_sent.")
            self.body_service.update_mail_body_times_sent(body_list[0])
            mail_instance.mail_body = body_list[0]
        else:
            fetch_mail_logger.error("No existing mail body found, creating new one.")
            body = self.body_service.create_mail_body_instance(data.reportedText)
            if body:
                self.body_service.save_mail_body_instance(body)
                mail_instance.mail_body = body

        if header_list:
            fetch_mail_logger.error("Existing mail header found, updating times_sent.")
            self.header_service.update_mail_header_times_sent(header_list[0])
            mail_instance.mail_header = header_list[0]
        else:
            fetch_mail_logger.error("No existing mail header found, creating new one.")
            header = self.header_service.create_mail_header_instance(str(data.headers))
            if header:
                self.header_service.save_mail_header_instance(header)
                mail_instance.mail_header = header

        return self._save_mail(mail_instance)

    def _process_rich_observables(self, mail_instance: Mail, data: EmailDataModel, workdir: str) -> None:
        """
        Processes observables linked to the mail for further enrichment.
        """
        self.observables_service.handle_rich_observables(
            mail_instance.mail_id, mail_instance, data.dict(), workdir
        )

    def _save_mail(self, mail_instance: Mail) -> Optional[Mail]:
        """
        Safely saves the mail instance.
        """
        with safe_operation("save_mail"):
            mail_instance.save()
            return mail_instance

    def _update_times_sent(self, mail_instance: Mail) -> None:
        """
        Increments and persists the number of times an email was sent.
        """
        increment_field(mail_instance, "times_sent")
        with safe_operation("update_mail_times_sent"):
            mail_instance.save()
