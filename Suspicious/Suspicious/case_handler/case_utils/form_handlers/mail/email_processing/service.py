# email_processing/service.py

import os
import shutil
import logging
from pathlib import Path
from typing import Optional
from email.message import EmailMessage

from case_handler.case_utils.form_handlers.mail.email_processing.utils import generate_object_reference
from case_handler.case_utils.form_handlers.mail.email_processing.parser import EmailParser
from case_handler.case_utils.form_handlers.mail.email_processing.saver import EmailSaver

logger = logging.getLogger(__name__)

class ProcessEmailService:
    """
    Orchestrates email processing: parsing content, saving files,
    moving attachments, and returning structured data or a Mail entity.
    """

    def process_submitted_email(self, msg: EmailMessage, submitter: str, tmp_dir: str) -> Optional[dict]:
        """
        Process an EmailMessage:
        - Save raw EML temporarily
        - Parse content and attachments with EmailParser
        - Move attachments dir to final structure
        - Save all parsed output with EmailSaver
        Args:
            msg: The email message object to process.
            submitter: Identifier for the submitting user.
            tmp_dir: Temporary directory to hold processing files.
        Returns:
            dict containing parsed email data, or None on failure.
        """
        source_ref = generate_object_reference()
        tmp_path = Path(tmp_dir)
        tmp_path.mkdir(parents=True, exist_ok=True)

        # 1. write initial .eml
        temp_eml = tmp_path / f"{submitter}-submission.eml"
        try:
            temp_eml.write_bytes(msg.as_bytes())
        except Exception as e:
            logger.error("Failed to write initial EML: %s", e)
            return None

        # 2. parse email content
        parser = EmailParser(tmp_path, source_ref)
        data = parser.parse(msg)

        # 3. rename eml to final reference
        final_eml = tmp_path / f"{source_ref}.eml"
        try:
            temp_eml.rename(final_eml)
        except Exception as e:
            logger.error("Failed to rename EML file: %s", e)
            return None

        # 4. move attachments directory if exists
        attach_dir = tmp_path / "attachments"
        if not attach_dir.exists():
            attach_dir.mkdir()
        elif attach_dir.is_file():
            logger.warning("Expected dir at %s but found file; recreating dir.", attach_dir)
            attach_dir.unlink()
            attach_dir.mkdir()

        # 5. save email components
        saver = EmailSaver(tmp_path)
        saver.save(
            ref=source_ref,
            eml_bytes=data.get("raw_eml_bytes"),
            body_text=data.get("body_text"),
            body_html=data.get("body_html"),
            headers=data.get("headers_parsed")
        )

        # 6. Return structured data
        return { **data, "source_ref": source_ref, "tmp_dir": str(tmp_path) }
