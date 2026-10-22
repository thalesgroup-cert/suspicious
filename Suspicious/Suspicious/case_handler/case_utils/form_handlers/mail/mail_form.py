import logging
import os
import re
import shutil
import unicodedata
from email import policy
from email.parser import BytesParser
from pathlib import Path

from mail_feeder.web_submission.web import WebSubmissionService
from mail_feeder.web_submission.models import WebSubmissionConfig

from case_handler.case_utils.form_handlers.mail.converters import convert_msg_to_eml
from case_handler.case_utils.form_handlers.mail.email_processing.service import ProcessEmailService
from case_handler.case_utils.form_handlers.mail.email_processing.utils import generate_object_reference
from case_handler.case_utils.form_handlers.mail.minio import MinioManager

logger = logging.getLogger(__name__)

DEFAULT_CASE_BASE_PATH = Path("/app/case")

_BUCKET_MAX_LEN = 63
_BUCKET_INFIX = "-submission-"

# One shared bucket for every web upload; each submission is a key prefix in it.
# A bucket per submission made the legacy scanner's list-and-tag scan grow
# without bound. The bucket carries no Status tag, so that scanner skips it.
DEFAULT_WEB_BUCKET = "mail-submissions"


def web_submission_bucket() -> str:
    """Shared bucket for web uploads (``storage.s3.web_bucket``)."""
    from settings.config import get_section
    return ((get_section("storage.s3") or {}).get("web_bucket") or DEFAULT_WEB_BUCKET).strip()


def bucket_name_for(user_prefix: str, mail_id: str) -> str:
    """S3-safe id of a web submission: ``<prefix>-submission-<stamp>``.

    Used as the key prefix inside the shared bucket and as the local directory
    name; it stays bucket-name-valid so it is also a legal name for the legacy
    layout.

    ``user_prefix`` is the local part of the username and can carry anything
    (uppercase, ``_``, ``.``, non-ASCII), none of which an S3 bucket allows.
    It is folded to ``[a-z0-9-]``, repeated hyphens are collapsed and the
    prefix is cut so the whole name stays within 63 characters, always
    keeping the unique timestamp suffix. An empty result becomes ``user``.
    """
    stamp = re.sub(r"[^a-z0-9]", "", mail_id.split("-", 1)[0].lower())
    ascii_prefix = unicodedata.normalize("NFKD", user_prefix).encode("ascii", "ignore").decode()
    prefix = re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]", "-", ascii_prefix.lower())).strip("-")
    room = _BUCKET_MAX_LEN - len(_BUCKET_INFIX) - len(stamp)
    return f"{prefix[:room].strip('-') or 'user'}{_BUCKET_INFIX}{stamp}"


class MailFormHandler:
    """
    Handles mail file uploads (.eml or .msg): converts, saves locally, processes, and uploads to MinIO.
    """

    def __init__(self, user, base_path: str = DEFAULT_CASE_BASE_PATH):
        """
        Args:
            user: Django User instance with username attribute.
            base_path: Local filesystem base directory where mail files are saved.
        """
        self.user = user
        self.base_path = Path(base_path)
        self.minio = MinioManager()

    def handle(self, mail_file):
        """
        Main handler for mail upload.

        Workflow:
        1. Validate extension (.eml or .msg).
        2. Convert .msg to .eml if needed.
        3. Create local directory to store the mail.
        4. Parse email, process content and attachments.
        5. Upload local directory to MinIO.
        6. Archive directory and process using WebSubmissionService.

        Returns:
            instance from WebSubmissionService or None on failure.
        """
        # os.path.basename strips any separator a username could carry: Django's
        # default validator already forbids "/", but this is the barrier CodeQL's
        # path-injection query recognizes, and it's what actually stops every
        # downstream directory built from user_prefix (object prefix, local_dir, tmp_dir)
        # from being flagged as tainted.
        user_prefix = os.path.basename(self.user.username.split('@')[0])
        mail_id = generate_object_reference()
        submission_id = bucket_name_for(user_prefix, mail_id)
        # The id above is only second-resolution; the random tail of mail_id keeps
        # two uploads of one user in the same second from sharing (and overwriting
        # each other's files under) one object prefix.
        object_prefix = "-".join(filter(None, (submission_id, mail_id.partition("-")[2])))
        ext = Path(mail_file.name).suffix.lower()

        if ext not in ('.eml', '.msg'):
            logger.error("Unsupported extension: %s", ext)
            return None

        temp = Path(mail_file.temporary_file_path())
        try:
            if ext == '.msg':
                temp = Path(convert_msg_to_eml(str(temp)))
        except Exception as e:
            logger.error("Conversion from .msg to .eml failed: %s", e)
            return None

        local_dir = self.base_path / submission_id / temp.stem
        local_dir.mkdir(parents=True, exist_ok=True)

        dest = local_dir / "user_submission.eml"
        try:
            shutil.move(str(temp), str(dest))
        except Exception as e:
            logger.error("Moving file to local directory failed: %s", e)
            return None

        try:
            with dest.open('rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            ProcessEmailService.process_submitted_email(self, msg, user_prefix, str(local_dir))
        except Exception as e:
            logger.error("Email parsing or processing failed: %s", e)
            return None

        if not self.minio.client:
            logger.critical("MinIO client unavailable, abort.")
            return None

        self.minio.upload_directory(source_dir=local_dir,
                                    bucket_name=web_submission_bucket(),
                                    base_object_path=object_prefix,
                                    tag_bucket=False)

        try:
            shutil.make_archive(str(local_dir), 'gztar', root_dir=str(local_dir))
        except Exception as e:
            logger.warning("Failed to archive directory: %s", e)

        try:
            instance = WebSubmissionService().process_emails(
                WebSubmissionConfig(user_email=self.user.username, workdir=str(local_dir))
            )
            return instance
        except Exception as e:
            logger.error("Final email processing failed: %s", e)
            return None

    def cleanup_directory(self, dir_path: Path, remove_parent_if_empty: bool = False):
        """
        Removes a directory and all its contents.
        Optionally removes the parent directory if it becomes empty after this deletion.

        Args:
            dir_path: Path object of the directory to remove.
            remove_parent_if_empty: If True, attempts to remove the parent directory
                                    if it's empty after dir_path is removed.
        """
        if not dir_path.exists():
            logger.warning(f"Directory '{dir_path}' not found for cleanup.")
            return

        try:
            shutil.rmtree(dir_path)
            logger.info(f"Successfully removed directory: {dir_path}")
            if remove_parent_if_empty:
                parent_dir = dir_path.parent
                if parent_dir.exists() and not any(parent_dir.iterdir()):
                    try:
                        parent_dir.rmdir()
                        logger.info(f"Successfully removed empty parent directory: {parent_dir}")
                    except OSError as e:
                        logger.warning(f"Could not remove parent directory {parent_dir} (it might not be empty or permission issue): {e}")
        except OSError as e:
            logger.error(f"Failed to delete directory '{dir_path}'. Reason: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during cleanup of '{dir_path}': {e}", exc_info=True)

