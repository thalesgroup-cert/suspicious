import logging
from typing import Dict

from django.db import transaction
from file_process.file_utils.file_handler import FileHandler
from mail_feeder.models import MailAttachment

from .models import AttachmentBatchModel
from .utils import safe_execution


logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

class AttachmentService:
    """
    Service responsible for processing mail attachments,
    validating input, and persisting records to the database.
    """

    def __init__(self):
        self.logger = logger

    def handle_attachments(self, files: Dict[str, object], mail_instance) -> None:
        """
        Main entry point: validate and process all attachments for a mail instance.
        """
        batch = AttachmentBatchModel(files=files)
        for file_obj in batch.files.values():
            self._process_single_attachment(file_obj, mail_instance)

        # Persist final mail state after processing all attachments
        mail_instance.save()
        self.logger.debug("All attachments processed and mail instance saved.")

    def _process_single_attachment(self, file_obj, mail_instance) -> None:
        """
        Handle a single file attachment, validate, store, and link to the mail instance.
        """
        with safe_execution(context=f"processing {file_obj.name}"):
            filename = file_obj.name
            self.logger.debug(f"Processing attachment: {filename}")

            # FileHandler is assumed to return (FileModel, created: bool)
            att, _ = FileHandler.handle_file(file=None, mail=filename)
            if att is None:
                self.logger.warning(f"FileHandler returned None for {filename}")
                return

            self._save_attachment_record(att, mail_instance)

    def _save_attachment_record(self, file_obj, mail_instance) -> None:
        """
        Persist a MailAttachment entry linking the mail and file.
        """
        with transaction.atomic(), safe_execution(context="database save"):
            mail_attachment = MailAttachment(mail=mail_instance, file=file_obj)
            mail_attachment.save()
            self.logger.debug(f"MailAttachment created for file {file_obj}")
