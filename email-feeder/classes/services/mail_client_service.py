import imaplib
import logging
import ssl
import time


import classes.models.mail_exceptions
import classes.models.configs.internals.imap


# --- Configuration & Constants ---
MAILBOX_LOGGER_NAME = "email-feeder.mailbox"
ATTACHMENTS_DIR_NAME = "attachments"
ANALYSIS_DIR_PREFIX = "analysis_"
USER_SUBMISSION_PREFIX = "user_submission_"


class MailClient:
    __imap_client: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None

    def __init__(
        self,
        config: classes.models.configs.internals.imap.IMAPConfig,
        logger: logging.Logger,
    ):
        self.__instance_config = config

        self.__use_ssl = (
            self.__instance_config.certfile is not None
            and self.__instance_config.keyfile is not None
        )

        self.__logger = logger

    def _reconnect(self, attempt_max: int = 3):
        """Force a clean reconnect to IMAP server."""
        self.__logger.warning("IMAP connection lost — attempting reconnection")

        # Always drop the broken client
        try:
            if self.__imap_client is not None:
                self.__imap_client.shutdown()
        except Exception:
            pass
        finally:
            self.__imap_client = None

        backoff = 1
        for attempt in range(1, attempt_max + 1):
            try:
                self.login()
                self.__logger.info(f"Reconnected on attempt {attempt}")
                return
            except Exception as e:
                self.__logger.error(
                    f"Reconnect attempt {attempt}/{attempt_max} failed: {e}"
                )
                if attempt == attempt_max:
                    raise
                time.sleep(backoff)
                backoff *= 2

    def _safe_op(self, func, *args, **kwargs):
        """Execute IMAP operation and reconnect transparently on broken pipe."""
        try:
            return func(*args, **kwargs)

        except (BrokenPipeError,
                imaplib.IMAP4.abort,
                OSError) as e:
            self.__logger.warning(f"IMAP error detected: {e} — reconnecting")
            self._reconnect()

            # Retry the operation ONCE after reconnection
            return func(*args, **kwargs)


    def login(self):
        """Connects and logs into the IMAP server."""
        if (
            self.__imap_client is not None
            and getattr(self.__imap_client, "state", None) == "SELECTED"
        ):
            pass

        try:
            if self.__use_ssl:
                self.__imaps_login()
            else:
                self.__imap_login()
            self.__logger.info(
                f"Successfully connected to IMAP{'S' if self.__use_ssl else ''} "
                f"server {self.__instance_config.host} as {self.__instance_config.login}"
            )
        except (
            imaplib.IMAP4.error,
            ssl.SSLError,
            OSError,
            ConnectionRefusedError,
        ) as e:
            # Catch more specific errors related to connection/authentication
            error_msg = f"Failed to connect/login to mailbox {self.__instance_config.login} on {self.__instance_config.host}: {repr(e)}"
            self.__logger.error(error_msg)
            raise classes.models.mail_exceptions.MailboxConnectionError(
                error_msg
            ) from e

    def __imap_login(self):
        """Handles non-SSL IMAP login."""
        self.__imap_client = imaplib.IMAP4(
            self.__instance_config.host, self.__instance_config.port
        )
        self.__imap_client.login(
            user=self.__instance_config.login, password=self.__instance_config.password
        )

    def __imaps_login(self):
        """Handles SSL IMAP login."""
        ssl_context = None

        if (not self.__use_ssl):
            raise Exception(
                "Trying to use SSL although no certfile / keyfile were provided."
            )

        ssl_context=ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.__instance_config.rootcafile)
        try:
            ssl_context.load_cert_chain(
                self.__instance_config.certfile, self.__instance_config.keyfile
            )
        except ssl.SSLError as e:
            self.__logger.error(
                f"SSL Error loading cert / key for {self.__instance_config.login}: {e}"
            )
            raise classes.models.mail_exceptions.MailboxConnectionError(
                f"SSL cert / key error: {e}"
            ) from e

        self.__imap_client = imaplib.IMAP4_SSL(
            self.__instance_config.host,
            self.__instance_config.port,
            ssl_context=ssl_context,
        )
        self.__imap_client.login(
            user=self.__instance_config.login, password=self.__instance_config.password
        )

    def logout(self):
        """Logs out and closes the IMAP connection."""
        if self.__imap_client is None:
            return

        try:
            if self.__imap_client.state in ("AUTH", "SELECTED"):
                self.__logger.info(
                    f"Logging out {self.__instance_config.login} from {self.__instance_config.host}"
                )
                self.__imap_client.logout()
            else:
                self.__imap_client.shutdown()
        except (imaplib.IMAP4.error, OSError) as e:
            self.__logger.warning(
                f"Error during logout for {self.__instance_config.login} (state: {getattr(self.__imap_client, 'state', 'N/A')}): {repr(e)}"
            )
        except AttributeError:
            self.__logger.warning(
                f"Could not determine IMAP server state or shutdown for {self.__instance_config.login}"
            )
        finally:
            self.__imap_client = None

    def __store(self, email_id: str, flags: str):
        if self.__imap_client is None:
            raise classes.models.mail_exceptions.MailboxConnectionError(
                "The IMAP client is not connected"
            )

        return self._safe_op(
            self.__imap_client.store,
            email_id,
            "+FLAGS",
            flags
        )

    def mark_email_as_seen(self, email_id: str):
        if self.__imap_client is None or self.__imap_client.state not in (
            "AUTH",
            "SELECTED",
        ):
            raise classes.models.mail_exceptions.MailboxConnectionError(
                "No mailbox selected. Cannot mark emails as seen."
            )

        store_flag = "\\Seen"

        try:
            response_status, response = self.__store(
                email_id=email_id, flags=store_flag
            )
        except imaplib.IMAP4.error as e:
            error_msg = (
                f"Error marking emails as seen in {self.__instance_config.mailbox_to_monitor} "
                f"for {self.__instance_config.login}: {repr(e)}"
            )
            raise classes.models.mail_exceptions.MailboxOperationError(error_msg) from e

        if response_status == "OK":
            return response_status, response

        error_detail = (
            response[0].decode("utf-8", "replace")
            if len(response) > 0 and response[0] is not None
            else "Unknown error"
        )
        raise classes.models.mail_exceptions.MailboxOperationError(
            f"Failed to store {store_flag} flag: {error_detail}"
        )

    def select(self, mailbox: str, readonly: bool = False):
        if self.__imap_client is None:
            raise classes.models.mail_exceptions.MailboxConnectionError(
                "The IMAP client is not connected"
            )

        response_status, response = self._safe_op(
            self.__imap_client.select,
            mailbox,
            readonly=readonly
        )

        if response_status == "OK":
            return response_status, response

        raise classes.models.mail_exceptions.MailboxOperationError(
            f"Failed to select mailbox '{mailbox}'"
        )


    def search(self, charset: str | None, *criteria: str):
        if self.__imap_client is None:
            raise classes.models.mail_exceptions.MailboxConnectionError(
                "The IMAP client is not connected"
            )

        response_status, response = self._safe_op(
            self.__imap_client.search,
            charset, *criteria
        )

        if response_status == "OK":
            return response_status, response

        raise classes.models.mail_exceptions.MailboxOperationError("Email lookup failed")


    def fetch(self, email_id: bytes, message_parts: str):
        if self.__imap_client is None:
            raise classes.models.mail_exceptions.MailboxConnectionError(
                "The IMAP client is not connected"
            )

        response_status, response = self._safe_op(
            self.__imap_client.fetch,
            email_id.decode("utf-8"),
            message_parts
        )

        is_ok = (
            response_status == "OK"
            and response
            and len(response) >= 1
            and isinstance(response[0], tuple)
        )

        if is_ok:
            return response_status, response

        raise classes.models.mail_exceptions.MailboxOperationError(
            f"Failed to fetch email {email_id}"
        )


    @property
    def is_logged_in(self) -> bool:
        return self.__imap_client is not None
