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
_IMAP_TIMEOUT = 30  # seconds — bound socket connect + SSL handshake


class MailClient:
    __imap_client: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None

    def __init__(
        self,
        config: classes.models.configs.internals.imap.IMAPConfig,
        logger: logging.Logger,
    ):
        self.__instance_config = config

        # TLS is driven by the connector type ('imaps' → use_ssl), NOT by the
        # presence of a client certificate. Tying it to cert presence silently
        # downgraded password-auth imaps connectors to plaintext IMAP, leaking
        # the mailbox password on the wire. Client cert/key are an optional
        # extra *inside* the TLS handshake (mutual TLS).
        self.__use_ssl = self.__instance_config.use_ssl
        self.__use_client_cert = (
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

    def _safe_op(self, method_name: str, *args, **kwargs):
        """Execute an IMAP operation by name and reconnect transparently on a
        broken pipe.

        The method is resolved against ``self.__imap_client`` at call time —
        both before and after a reconnect — so the retry runs against the
        freshly reconnected client. Passing a pre-bound method instead would
        retry against the dead client and always fail.
        """
        client = self.__imap_client
        if client is None:
            raise classes.models.mail_exceptions.MailboxConnectionError(
                "The IMAP client is not connected"
            )
        try:
            return getattr(client, method_name)(*args, **kwargs)

        except (BrokenPipeError,
                imaplib.IMAP4.abort,
                OSError) as e:
            self.__logger.warning(f"IMAP error detected: {e} — reconnecting")
            self._reconnect()

            if self.__imap_client is None:
                raise classes.models.mail_exceptions.MailboxConnectionError(
                    "IMAP client unavailable after reconnect"
                )

            # Retry the operation ONCE against the reconnected client.
            return getattr(self.__imap_client, method_name)(*args, **kwargs)


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
            self.__instance_config.host,
            self.__instance_config.port,
            timeout=_IMAP_TIMEOUT,
        )
        self.__imap_client.login(
            user=self.__instance_config.login, password=self.__instance_config.password
        )

    def __imaps_login(self):
        """Handles SSL IMAP login."""
        if not self.__use_ssl:
            raise Exception("Trying to use SSL on a non-SSL connector.")

        ssl_context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=self.__instance_config.rootcafile
        )
        # Client certificate is optional: only load a cert chain when both a
        # certfile and keyfile are configured (mutual-TLS deployments).
        if self.__use_client_cert:
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
            timeout=_IMAP_TIMEOUT,
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
            "store",
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
            "select",
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
            "search",
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
            "fetch",
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

    def has_idle_capability(self) -> bool:
        """True when the connected server advertises the IDLE extension."""
        client = self.__imap_client
        if client is None:
            return False
        try:
            return "IDLE" in getattr(client, "capabilities", ())
        except Exception:
            return False

    def idle_wait(self, timeout: float) -> bool:
        """Block in IMAP IDLE until new mail arrives or `timeout` elapses.

        Returns True if woken by a mailbox change, False on timeout/error.
        EXPERIMENTAL: uses raw imaplib internals; needs live (greenmail)
        verification before enabling in production. Best-effort — any hiccup
        returns False and always issues DONE so the connection stays usable.
        """
        import socket

        client = self.__imap_client
        if client is None:
            return False
        tag = client._new_tag()
        woke = False
        try:
            client.send(b"%s IDLE\r\n" % tag)
            if not client.readline().startswith(b"+"):
                return False
            client.sock.settimeout(timeout)
            try:
                while True:
                    line = client.readline()
                    if not line:
                        break
                    if b"EXISTS" in line or b"RECENT" in line:
                        woke = True
                        break
            except (socket.timeout, OSError):
                pass
        except Exception as e:  # noqa: BLE001
            self.__logger.warning(f"IDLE wait error: {e}")
        finally:
            try:
                client.send(b"DONE\r\n")
                client.sock.settimeout(5)
                for _ in range(10):
                    line = client.readline()
                    if not line or line.startswith(tag):
                        break
            except Exception:
                pass
            try:
                client.sock.settimeout(_IMAP_TIMEOUT)
            except Exception:
                pass
        return woke
