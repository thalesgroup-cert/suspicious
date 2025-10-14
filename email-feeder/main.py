import time
import shutil
import pathlib
import sys

import classes.models.configs.main_config
import classes.services.config_service
import classes.services.minio_service
import classes.services.mailbox_setup_service
import classes.services.mailbox_service
import classes.services.acknowledge_bad_mail_service
import classes.services.logger_service

logger = classes.services.logger_service.setup_logging()


# --- Helper Functions ---


def cleanup_directory(dir_path: pathlib.Path, remove_parent_if_empty: bool = False):
    """
    Removes a directory and all its contents.
    typing.Optionally removes the parent directory if it becomes empty after this deletion.

    Args:
        dir_path: Path object of the directory to remove.
        remove_parent_if_empty: If True, attempts to remove the parent directory
                                if it's empty after dir_path is removed.
    """
    if not dir_path.exists():
        logger.warning(f"Directory '{dir_path}' not found for cleanup.")
        return None

    try:
        shutil.rmtree(dir_path)
        logger.info(f"Successfully removed directory: {dir_path}")
    except OSError as e:
        logger.error(f"Failed to delete directory '{dir_path}'. Reason: {e}")
    except Exception as e:
        logger.error(
            f"Unexpected error during cleanup of '{dir_path}': {e}", exc_info=True
        )

    if not remove_parent_if_empty:
        return None

    parent_dir = dir_path.parent
    if not parent_dir.exists() or not any(parent_dir.iterdir()):
        return None

    try:
        parent_dir.rmdir()
        logger.info(f"Successfully removed empty parent directory: {parent_dir}")
    except OSError as e:
        logger.warning(
            f"Could not remove parent directory {parent_dir} (it might not be empty or permission issue): {e}"
        )


# --- Email Processing ---


def process_emails_from_mailboxes(
    config: classes.models.configs.main_config.MainConfig,
    acknowledge_bad_mail_service: classes.services.acknowledge_bad_mail_service.AcknowledgeBadMailService,
    mailboxes: list[classes.services.mailbox_service.Mailbox],
    minio_service: classes.services.minio_service.MinioService,
):
    """
    Fetches and processes emails from all enabled mailboxes.
    """
    if not mailboxes:
        logger.info("No mailboxes provided to process.")
        return

    for mailbox in mailboxes:
        mailbox_identifier = mailbox.config.login or mailbox.config.host
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
                case_path = pathlib.Path(mail.case_path)
                acknowledge_bad_mail_service.process_single_email(
                    mail=mail, case_path=case_path
                )

            for case_dir in config.working_path.iterdir():
                if case_dir.is_dir():
                    bucket_name = case_dir.name.lower().replace("_", "-")
                    minio_service.upload_directory(case_dir, bucket_name)
                    cleanup_directory(case_dir, remove_parent_if_empty=False)
                    logger.info(f"Cleaned up case directory: {case_dir}")

            email_ids = [email.original_mail.id for email in email_list]
            mailbox.mark_emails_as_seen(email_ids=email_ids)
            logger.info(f"Marked emails as seen for mailbox: {mailbox_identifier}.")

        except Exception as e:
            logger.error(
                f"Error processing mailbox {mailbox_identifier}: {e}",
                exc_info=True,
            )
        logger.info(f"Finished processing cycle for mailbox: {mailbox_identifier}.")


# --- Main Application Logic ---


def main() -> int:
    """
    Main function to initialize and run the email processing loop.
    """
    logger.info("Application starting...")

    try:
        config = classes.services.config_service.load_config(
            config_path=pathlib.Path("config.json"), logger=logger
        )
        if not config:
            logger.critical("Configuration could not be loaded. Exiting.")
            return 1
    except FileNotFoundError:
        logger.critical("Configuration file (e.g., config.json) not found. Exiting.")
        return 1
    except Exception as e:
        logger.critical(f"Failed to load configuration: {e}", exc_info=True)
        return 1

    acknowledge_bad_mail_service = (
        classes.services.acknowledge_bad_mail_service.AcknowledgeBadMailService(
            config=config.mail, logger=logger
        )
    )

    minio_service = classes.services.minio_service.MinioService(config.minio)
    try:
        minio_service.connect()
        logger.info("MinIO client initialized from config.")
    except Exception as e:
        logger.critical(f"Failed to initialize MinIO client from config: {e}")
        return 1

    try:
        logger.info("Setting up mailboxes...")
        mailboxes = classes.services.mailbox_setup_service.setup_mailboxes(
            config=config,
            logger=logger,
        )
        if not mailboxes:
            logger.warning(
                "No mailboxes configured or failed to connect. Check logs from setup_mailboxes. Exiting."
            )
            return 1
        logger.info(f"Successfully connected to {len(mailboxes)} mailboxes.")
    except Exception as e:
        logger.critical(f"Failed to setup mailboxes: {e}", exc_info=True)
        return 1

    try:
        config.working_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Using case processing path: {config.working_path}")
    except OSError as e:
        logger.error(
            f"Could not create or access case processing path '{config.working_path}': {e}. Check permissions."
        )
        return 1

    sleep_interval = config.timer_inbox_emails
    if sleep_interval <= 0:
        logger.warning(
            f"Invalid 'timer-inbox-emails' value ({sleep_interval}). Using default: {config.timer_inbox_emails}s."
        )
        sleep_interval = config.timer_inbox_emails

    logger.info(f"Starting email processing loop. Interval: {sleep_interval}s")
    try:
        while True:
            logger.info("Starting new email processing cycle...")
            process_emails_from_mailboxes(
                config=config,
                acknowledge_bad_mail_service=acknowledge_bad_mail_service,
                mailboxes=mailboxes,
                minio_service=minio_service,
            )
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
        return 1

    logger.info("Application finished.")
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
