import time
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional

from minio import Minio
from minio.error import S3Error
from minio.commonconfig import Tags

from setup import (
    setup_logging,
    get_logger,
    setup_config,
    setup_mailboxes,
)

from classes.acknowledge_bad_mail_service import (
    AcknowledgeBadMailService,
    AcknowledgeBadMailServiceConfigSocial,
    SOCIAL_LOGOS,
)

import classes.send_mail_service as send_mail_service


# --- Configuration & Constants ---
setup_logging()
logger = get_logger()

# Tagging constants
TAG_STATUS_TODO = "To Do"
TAG_KEY_STATUS = "Status"
TAG_RESEND = "to_resend"

# Constants for retry logic
MAX_RETRIES = 3
BASE_DELAY = 1  # in seconds

# Default application paths and settings
DEFAULT_CASE_BASE_PATH = Path("/app/case")
DEFAULT_SLEEP_INTERVAL = 10  # seconds

# --- Helper Functions ---


def ensure_bucket_exists_and_tagged(
    client: Minio, bucket_name: str, tags_to_set: Optional[Dict[str, str]] = None
) -> bool:
    """
    Ensures a MinIO bucket exists. If not, creates it and applies tags.
    If it exists, checks if tags need to be updated (optional behavior, currently only sets on creation).

    Args:
        client: Initialized MinIO client.
        bucket_name: Name of the bucket.
        tags_to_set: A dictionary of tags to apply if the bucket is created.

    Returns:
        True if the bucket exists (or was created), False on error.
    """
    if not client:
        logger.error(f"MinIO client not available for bucket '{bucket_name}'.")
        return False
    try:
        if not client.bucket_exists(bucket_name):
            client.make_bucket(bucket_name)
            logger.info(f"Created MinIO bucket '{bucket_name}'.")
            if tags_to_set:
                bucket_tags = Tags()
                for key, value in tags_to_set.items():
                    bucket_tags[key] = value
                client.set_bucket_tags(bucket_name, bucket_tags)
                logger.info(f"Set tags for bucket '{bucket_name}': {tags_to_set}")
        else:
            logger.info(f"MinIO bucket '{bucket_name}' already exists.")

        return True
    except S3Error as e:
        logger.error(f"MinIO S3Error concerning bucket '{bucket_name}': {e}")
    except Exception as e:
        logger.error(
            f"Unexpected error concerning bucket '{bucket_name}': {e}", exc_info=True
        )
    return False


def upload_directory_to_minio(
    client: Minio,
    source_dir: Path,
    bucket_name: str,
    base_object_path: str = "",
    default_tags: Optional[Dict[str, str]] = None,
):
    """
    Uploads all files from a local directory to a specified MinIO bucket and path.
    Optionally applies default tags to each uploaded object.

    Args:
        client: Initialized MinIO client.
        source_dir: Path object for the local directory to upload.
        bucket_name: Name of the target MinIO bucket.
        base_object_path: Optional base path within the bucket for uploaded objects.
        default_tags: Optional dictionary of tags to apply to each object.
    """
    if not client:
        logger.error(f"MinIO client not available for uploading to '{bucket_name}'.")
        return
    if not source_dir.is_dir():
        logger.error(f"Source '{source_dir}' is not a directory or does not exist.")
        return

    bucket_creation_tags = {TAG_KEY_STATUS: TAG_STATUS_TODO}
    if not ensure_bucket_exists_and_tagged(client, bucket_name, bucket_creation_tags):
        logger.error(
            f"Cannot upload to MinIO bucket '{bucket_name}' as it could not be ensured/created."
        )
        return

    for file_path in source_dir.rglob("*"):
        if file_path.is_file():
            relative_path_str = str(file_path.relative_to(source_dir)).replace(
                "\\", "/"
            )
            object_name = (
                f"{base_object_path.rstrip('/')}/{relative_path_str}"
                if base_object_path
                else relative_path_str
            )

            object_tags = Tags(for_object=True)
            if default_tags:
                for k, v in default_tags.items():
                    object_tags[k] = v

            try:
                with open(file_path, "rb") as f_data:
                    file_stat = file_path.stat()
                    client.put_object(
                        bucket_name=bucket_name,
                        object_name=object_name,
                        data=f_data,
                        length=file_stat.st_size,
                        content_type="application/octet-stream",
                        tags=object_tags if default_tags else None,
                    )
                logger.info(
                    f"Uploaded '{file_path.name}' to '{bucket_name}/{object_name}' with tags: {default_tags or 'None'}."
                )
            except S3Error as e:
                logger.error(
                    f"MinIO S3Error uploading '{file_path.name}' as '{object_name}': {e}"
                )
            except Exception as e:
                logger.error(
                    f"Failed to upload '{file_path.name}' as '{object_name}': {e}",
                    exc_info=True,
                )


def cleanup_directory(dir_path: Path, remove_parent_if_empty: bool = False):
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
                    logger.info(
                        f"Successfully removed empty parent directory: {parent_dir}"
                    )
                except OSError as e:
                    logger.warning(
                        f"Could not remove parent directory {parent_dir} (it might not be empty or permission issue): {e}"
                    )
    except OSError as e:
        logger.error(f"Failed to delete directory '{dir_path}'. Reason: {e}")
    except Exception as e:
        logger.error(
            f"Unexpected error during cleanup of '{dir_path}': {e}", exc_info=True
        )


# --- Email Processing ---


def process_single_email(mail: Any, case_base_path: Path):
    """
    Processes a single email: uploads its case files to MinIO or prepares for resend, then cleans up.
    """
    mail_id = getattr(mail, "new_id", getattr(mail, "id", "UnknownID"))
    sender = getattr(mail, "sender", "UnknownSender")
    mail_tags = getattr(mail, "tags", None)

    case_path = Path(mail.case_path)

    logger.info(
        f"Processing mail ID: {mail_id} from sender: {sender} with case path: {case_path}"
    )

    if not case_path.is_dir():
        logger.error(
            f"Mail {mail_id}: Case path '{case_path}' does not exist or is not a directory. Skipping."
        )
        return

    if mail_tags == TAG_RESEND:
        # If the mail is tagged for resend, we prepare it for reprocessing.
        logger.info(
            f"Mail {mail_id} is tagged for resend. Preparing case files for reprocessing."
        )
        user_acknowledge(sender)
        logger.info(f"Mail {mail_id} tagged for resend. Notifying {sender}.")
        cleanup_directory(case_path, remove_parent_if_empty=True)
    else:
        # TODO: Acknowledment email
        logger.info(
            f"Mail {mail_id}: Standard processing. Uploading case files from '{case_path}'."
        )


def send_with_retry(send_callable, max_retries=MAX_RETRIES, base_delay=BASE_DELAY):
    """
    Helper function to attempt sending an email with retries using exponential backoff.

    Args:
        send_callable (callable): A callable that sends an email.
        max_retries (int): Maximum number of attempts.
        base_delay (int): Base delay (in seconds) before retrying.

    Returns:
        bool: True if send_callable() succeeds, False otherwise.
    """
    for attempt in range(1, max_retries + 1):
        try:
            send_callable()
            logger.info("Email sent successfully on attempt %d.", attempt)
            return True
        except Exception as e:
            logger.warning("Attempt %d failed: %s", attempt, e, exc_info=True)
            if attempt < max_retries:
                wait_time = base_delay * (2 ** (attempt - 1))
                logger.info("Retrying in %d seconds...", wait_time)
                time.sleep(wait_time)
    return False


def user_acknowledge(user: str):
    """
    Send an acknowledgement email to the user if the mail is received
    and the user hasn't been informed yet.
    """
    try:
        config = setup_config()
        if not config:
            logger.critical("Configuration could not be loaded. Exiting.")
            return
    except FileNotFoundError:
        logger.critical("Configuration file (e.g., config.json) not found. Exiting.")
        return
    except Exception as e:
        logger.critical(f"Failed to load configuration: {e}", exc_info=True)
        return

    mail_config = config.get("mail", {})
    logos = mail_config.get("logos", {})
    socials = mail_config.get("socials", {})

    acknowledge_bad_mail_service = AcknowledgeBadMailService(
        {
            "compagny_name": mail_config.get("group", "Your Compagny Team Name"),
            "compagny_logo": logos.get("compagny", "#"),
            "acknowledge_bad_mail_logo": logos.get("acknowledge-badmail", "#"),
            "compagny_global_security_team": mail_config.get(
                "global", "Global Security Team"
            ),
            "compagny_global_security_url": mail_config.get(
                "global_url", "https://example.com/global-security"
            ),
            "compagny_online_portal": mail_config.get(
                "submissions", "https://example.com/online-portal"
            ),
            "compagny_socials": [
                AcknowledgeBadMailServiceConfigSocial(
                    name=social,
                    url=socials.get(social, f"https://{social}.com"),
                    logo=SOCIAL_LOGOS.get(social, "#"),
                )
                for social in socials.keys()
            ],
            "glossary": mail_config.get("glossary", "https://glossary_to_cyber terms"),
            "inquiry": mail_config.get("inquiry", "mailto:inquryemail@yourcompany.com"),
            "inquiry_details": mail_config.get(
                "inquiry_text", "inquryemail@yourcompany.com"
            ),
        }
    )

    SUSPICIOUS_EMAIL = mail_config.get("username")
    try:
        # Build user info string if available
        user_ = user.split("@")[0]
        user_first_name = user_.split(".")[0] if "." in user_ else user_
        user_last_name = user_.split(".")[1] if "." in user_ else ""
        user_infos = f"{user_first_name} {user_last_name}"
        logger.info(
            "Sending acknowledgement email to user with user_infos: %s", user_infos
        )
        # Check user validity (ensuring user is not marked as "suspicious")
        if user is not None and user != "suspicious":

            def send_action():
                subject = "SUSPICIOUS EMAIL ANALYSIS - There is a problem with your submission"
                html = acknowledge_bad_mail_service.get_html(
                    subject=subject,
                    sender=str(SUSPICIOUS_EMAIL),
                    recipient=user,
                    infos=user_infos,
                )

                _service = send_mail_service.SendMailService(
                    host=mail_config["server"], port=mail_config.get("port", 587)
                )

                _service.connect()

                _service.publish_email(
                    subject=subject,
                    sender=str(SUSPICIOUS_EMAIL),
                    recipient=user,
                    html=html,
                )

                _service.close()

            if send_with_retry(send_action):
                logger.info("Acknowledgement email sent successfully")
            else:
                logger.error("Failed to send acknowledgement email.")
    except Exception as e:
        logger.error("Error sending acknowledgement email: %s", e, exc_info=True)


def process_emails_from_mailboxes(mailboxes: List[Any], case_processing_path: Path):
    """
    Fetches and processes emails from all enabled mailboxes.
    """
    if not mailboxes:
        logger.info("No mailboxes provided to process.")
        return

    for mailbox in mailboxes:
        mailbox_identifier = getattr(
            mailbox, "username", getattr(mailbox, "server", "UnknownMailbox")
        )
        logger.info(f"Checking mailbox: {mailbox_identifier}")
        try:
            email_list = mailbox.fetch_unseen_emails_and_process()

            if not email_list:
                logger.info(
                    f"No new emails to process in mailbox: {mailbox_identifier}"
                )
                continue

            logger.info(
                f"Fetched {len(email_list)} email(s) from {mailbox_identifier}."
            )
            for mail in email_list:
                process_single_email(mail, case_processing_path)
            for case_dir in DEFAULT_CASE_BASE_PATH.iterdir():
                if case_dir.is_dir():
                    bucket_name = case_dir.name.lower().replace("_", "-")
                    upload_directory_to_minio(minio_client, case_dir, bucket_name)
                    cleanup_directory(case_dir, remove_parent_if_empty=False)
                    logger.info(f"Cleaned up case directory: {case_dir}")
            if hasattr(mailbox, "mark_emails_as_seen"):
                mailbox.mark_emails_as_seen()
                logger.info(f"Marked emails as seen for mailbox: {mailbox_identifier}.")
            else:
                logger.warning(
                    f"Mailbox {mailbox_identifier} does not have 'mark_emails_as_seen' method."
                )

        except Exception as e:
            logger.error(
                f"Error processing mailbox {mailbox_identifier}: {e}",
                exc_info=True,
            )
        logger.info(f"Finished processing cycle for mailbox: {mailbox_identifier}.")


# --- Main Application Logic ---


def main():
    """
    Main function to initialize and run the email processing loop.
    """
    logger.info("Application starting...")
    global minio_client

    try:
        config = setup_config()
        if not config:
            logger.critical("Configuration could not be loaded. Exiting.")
            return
    except FileNotFoundError:
        logger.critical("Configuration file (e.g., config.json) not found. Exiting.")
        return
    except Exception as e:
        logger.critical(f"Failed to load configuration: {e}", exc_info=True)
        return

    minio_endpoint_cfg = config.get("minio", {}).get("endpoint", "localhost:9000")
    minio_access_key_cfg = config.get("minio", {}).get("access_key", "minioadmin")
    minio_secret_key_cfg = config.get("minio", {}).get("secret_key", "minioadmin")
    minio_secure_cfg = config.get("minio", {}).get("secure", False)
    try:
        minio_client = Minio(
            minio_endpoint_cfg,
            access_key=minio_access_key_cfg,
            secret_key=minio_secret_key_cfg,
            secure=minio_secure_cfg,
        )
        logger.info("MinIO client initialized from config.")
    except Exception as e:
        logger.critical(f"Failed to initialize MinIO client from config: {e}")
        minio_client = None

    if not minio_client:
        logger.critical(
            "MinIO client is not available. Email processing that requires MinIO will fail. Exiting."
        )
        return

    try:
        logger.info("Setting up mailboxes...")
        mailboxes = setup_mailboxes(config)
        if not mailboxes:
            logger.warning(
                "No mailboxes configured or failed to connect. Check logs from setup_mailboxes. Exiting."
            )
            return
        logger.info(f"Successfully connected to {len(mailboxes)} mailboxes.")
    except Exception as e:
        logger.critical(f"Failed to setup mailboxes: {e}", exc_info=True)
        return

    case_processing_path = Path(config.get("working-path", DEFAULT_CASE_BASE_PATH))
    try:
        case_processing_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Using case processing path: {case_processing_path}")
    except OSError as e:
        logger.error(
            f"Could not create or access case processing path '{case_processing_path}': {e}. Check permissions."
        )

    sleep_interval = config.get("timer-inbox-emails", DEFAULT_SLEEP_INTERVAL)
    if not isinstance(sleep_interval, (int, float)) or sleep_interval <= 0:
        logger.warning(
            f"Invalid 'timer-inbox-emails' value ({sleep_interval}). Using default: {DEFAULT_SLEEP_INTERVAL}s."
        )
        sleep_interval = DEFAULT_SLEEP_INTERVAL

    logger.info(f"Starting email processing loop. Interval: {sleep_interval}s")
    try:
        while True:
            logger.info("Starting new email processing cycle...")
            process_emails_from_mailboxes(mailboxes, case_processing_path)
            logger.info(
                f"Email processing cycle complete. Sleeping for {sleep_interval}s."
            )
            time.sleep(sleep_interval)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down application...")
    except Exception as e:
        logger.critical(
            f"An unexpected critical error occurred in the main loop: {e}",
            exc_info=True,
        )
    finally:
        logger.info("Application finished.")


if __name__ == "__main__":
    main()
