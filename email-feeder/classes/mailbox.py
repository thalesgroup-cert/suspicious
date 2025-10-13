import typing
import email
import email.utils
import email.message
import email.header
import email.policy
import hashlib
import imaplib
import mimetypes
import os
import re
import shutil
import ssl
import uuid
from datetime import datetime
from email.message import EmailMessage
from email.parser import HeaderParser

import chardet
from bs4 import BeautifulSoup
from classes.mail import Mail
from dateutil import parser, tz

# --- Configuration & Constants ---
import logging

logger = logging.getLogger("email-feeder.mailbox")

ATTACHMENTS_DIR_NAME = "attachments"
ANALYSIS_DIR_PREFIX = "analysis_"
USER_SUBMISSION_PREFIX = "user_submission_"


# --- Custom Exceptions for Better Error Handling ---
class MailboxConnectionError(Exception):
    """Custom exception for issues related to connecting to the mailbox."""

    pass


class MailboxOperationError(Exception):
    """Custom exception for errors during IMAP operations after connection."""

    pass


class Attachment(typing.TypedDict):
    filename: str
    file_path: str
    content: bytes
    headers: dict[str, list[typing.Any]]
    file_sha256: str | None
    parent: str


class MailboxParsedEmailData(typing.TypedDict):
    to: list[str]
    cc: list[str]
    bcc: list[str]
    date: str | None
    subject: str | None
    from_address: str | None
    from_header_raw: str | None
    attachments: list[Attachment]
    body_text: str
    body_html: str
    headers_parsed: email.message.Message | dict[str, str]
    raw_eml_bytes: bytes


class Mailbox:
    def __init__(
        self,
        server: str,
        port: int,
        username: str,
        password: str,
        tmp_dir: str,
        use_ssl: bool = True,
        certfile: str | None = None,
        keyfile: str | None = None,
        mailbox_to_monitor: str = "TEST",
    ):
        self.server = server
        self.port = int(port)
        self.username = username
        self.password = password
        self.tmp_dir = tmp_dir

        self.use_ssl = use_ssl
        self.certfile = certfile
        self.keyfile = keyfile
        self.mailbox_to_monitor = mailbox_to_monitor

        self.imap_server: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        self.fetched_unseen_email_ids: list[str] = []

    # --- Connection Management (Context Manager) ---
    def __enter__(self):
        """Enters the runtime context related to this object, calls login."""
        self.login()
        return self

    def __exit__(self):
        """Exits the runtime context, calls logout."""
        self.logout()

    def login(self):
        """Connects and logs into the IMAP server."""
        if self.imap_server and getattr(self.imap_server, "state", None) == "SELECTED":
            pass

        try:
            if self.use_ssl:
                self._imaps_login()
            else:
                self._imap_login()
            logger.info(
                f"Successfully connected to IMAP{'S' if self.use_ssl else ''} "
                f"server {self.server} as {self.username}"
            )
        except (
            imaplib.IMAP4.error,
            ssl.SSLError,
            OSError,
            ConnectionRefusedError,
        ) as e:
            # Catch more specific errors related to connection/authentication
            error_msg = f"Failed to connect/login to mailbox {self.username} on {self.server}: {repr(e)}"
            logger.error(error_msg)
            raise MailboxConnectionError(error_msg) from e

    def _imap_login(self):
        """Handles non-SSL IMAP login."""
        self.imap_server = imaplib.IMAP4(self.server, self.port)
        self.imap_server.login(self.username, self.password)

    def _imaps_login(self):
        """Handles SSL IMAP login."""
        ssl_context_to_use = None

        if self.certfile and self.keyfile:
            try:
                ssl_context_to_use = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context_to_use.load_cert_chain(self.certfile, self.keyfile)
            except ssl.SSLError as e:
                logger.error(f"SSL Error loading cert/key for {self.username}: {e}")
                raise MailboxConnectionError(f"SSL cert/key error: {e}") from e

        self.imap_server = imaplib.IMAP4_SSL(
            self.server, self.port, ssl_context=ssl_context_to_use
        )
        self.imap_server.login(self.username, self.password)

    def logout(self):
        """Logs out and closes the IMAP connection."""
        if self.imap_server:
            try:
                if self.imap_server.state in ["AUTH", "SELECTED"]:
                    logger.info(f"Logging out {self.username} from {self.server}")
                    self.imap_server.logout()
                else:
                    self.imap_server.shutdown()
            except (imaplib.IMAP4.error, OSError) as e:
                logger.warning(
                    f"Error during logout for {self.username} (state: {getattr(self.imap_server, 'state', 'N/A')}): {repr(e)}"
                )
            except AttributeError:
                logger.warning(
                    f"Could not determine IMAP server state or shutdown for {self.username}"
                )
            finally:
                self.imap_server = None

    # --- Email Operations ---
    def mark_emails_as_seen(self, email_ids_to_mark: list[str] | None = None):
        """Marks the specified email IDs (or cached fetched unseen emails) as seen."""
        if not self.imap_server or self.imap_server.state not in ["AUTH", "SELECTED"]:
            raise MailboxConnectionError(
                "Not connected or no mailbox selected. Cannot mark emails as seen."
            )

        ids_to_process = (
            email_ids_to_mark
            if email_ids_to_mark is not None
            else self.fetched_unseen_email_ids
        )

        if not ids_to_process:
            logger.debug("No email IDs provided or cached to mark as seen.")
            return

        # Ensure IDs are byte strings for joining, as received from search()
        valid_byte_ids = [eid for eid in ids_to_process if isinstance(eid, bytes)]
        if not valid_byte_ids:
            logger.warning("No valid byte-string email IDs to mark as seen.")
            return

        formatted_ids_str = b",".join(valid_byte_ids)

        try:
            logger.info(
                f"Marking {len(valid_byte_ids)} emails as seen in '{self.mailbox_to_monitor}'."
            )
            typ, response = self.imap_server.store(
                formatted_ids_str.decode("utf-8"), "+FLAGS", "\\Seen"
            )

            if typ != "OK":
                error_detail = (
                    response[0].decode("utf-8", "replace")
                    if response and response[0]
                    else "Unknown error"
                )
                raise MailboxOperationError(
                    f"Failed to store \\Seen flag: {error_detail}"
                )

            logger.info(
                f"Successfully marked emails as seen: {formatted_ids_str.decode('utf-8', 'replace')}"
            )

            if ids_to_process is self.fetched_unseen_email_ids:
                self.fetched_unseen_email_ids = []
        except (imaplib.IMAP4.error, OSError) as e:
            error_msg = (
                f"Error marking emails as seen in {self.mailbox_to_monitor} "
                f"for {self.username}: {repr(e)}"
            )
            logger.error(error_msg)
            raise MailboxOperationError(error_msg) from e

    def fetch_unseen_emails_and_process(self) -> list[Mail]:
        """
        Fetches unseen emails, processes them (including EML attachments),
        and caches their IDs to be potentially marked as seen later.
        Assumes 'process_inbox_email' and 'process_attachment_email' are methods of this class.
        """
        if not self.imap_server:
            raise MailboxConnectionError(
                "Not connected. Call login() first or use as context manager."
            )

        processed_mail_objects: list[Mail] = []
        try:
            # Select the mailbox (readonly=False allows subsequent STORE operations in the same session)
            typ, data = self.imap_server.select(self.mailbox_to_monitor, readonly=False)
            if typ != "OK":
                error_detail = (
                    data[0].decode("utf-8", "replace")
                    if data and data[0]
                    else "Unknown error"
                )
                raise MailboxOperationError(
                    f"Failed to select mailbox '{self.mailbox_to_monitor}': {error_detail}"
                )

            # Search for unseen emails. Consider using UID SEARCH for UIDs if preferred over sequence numbers.
            typ, search_data = self.imap_server.search(None, "(UNSEEN)")
            if typ != "OK":
                error_detail = (
                    search_data[0].decode("utf-8", "replace")
                    if search_data and search_data[0]
                    else "Unknown error"
                )
                raise MailboxOperationError(
                    f"Failed to search for unseen emails: {error_detail}"
                )
            if (
                not search_data or not search_data[0].strip()
            ):  # Check if empty or only whitespace
                logger.info(
                    f"No unseen emails found in '{self.mailbox_to_monitor}' for {self.username}."
                )
                self.fetched_unseen_email_ids = []
                return []

            # email_ids are space-separated bytes string of message numbers
            self.fetched_unseen_email_ids = search_data[0].split()
            logger.info(
                f"Found {len(self.fetched_unseen_email_ids)} unseen emails in "
                f"'{self.mailbox_to_monitor}' for {self.username}."
            )

        except (imaplib.IMAP4.error, OSError) as e:
            error_msg = (
                f"Error during email search in {self.mailbox_to_monitor} "
                f"for {self.username}: {repr(e)}"
            )
            logger.error(error_msg)
            raise MailboxOperationError(error_msg) from e

        # Process each fetched email ID
        for email_id_bytes in self.fetched_unseen_email_ids:
            try:
                source_ref = self.generate_object_reference()
                processed_main_email = self.process_inbox_email(
                    email_id_bytes, source_ref
                )

                if isinstance(processed_main_email, list):
                    eml_attachments_metadata, base_tmp_path, main_email_source_ref = (
                        processed_main_email
                    )

                    for i, att_meta in enumerate(eml_attachments_metadata):
                        try:
                            eml_file_path = att_meta.get("file_path")
                            if not eml_file_path or not os.path.exists(eml_file_path):
                                logger.error(
                                    f"EML attachment file not found or path missing: "
                                    f"'{att_meta.get('filename', 'N/A')}' from ref {main_email_source_ref}"
                                )
                                continue

                            with open(eml_file_path, "rb") as f_eml:
                                attached_msg = email.message_from_binary_file(
                                    f_eml, policy=email.policy.default
                                )

                            processed_attached_mail_obj = self.process_attachment_email(
                                attached_msg,
                                base_tmp_path,
                                source_ref=main_email_source_ref,
                            )
                            if processed_attached_mail_obj:
                                processed_mail_objects.append(
                                    processed_attached_mail_obj
                                )
                        except FileNotFoundError:
                            logger.error(
                                f"EML attachment file physically not found: '{eml_file_path}'"
                            )
                        except Exception as e_attach:
                            logger.error(
                                f"Failed to process EML attachment "
                                f"'{att_meta.get('filename', 'N/A')}': {repr(e_attach)}"
                            )
                elif processed_main_email:
                    processed_mail_objects.append(processed_main_email)
            except Exception as e_main_process:
                logger.error(
                    f"Error processing email ID {email_id_bytes.decode()}: {repr(e_main_process)}"
                )

        return processed_mail_objects

    # --- Utility ---
    def generate_object_reference(self):
        """Generates a more unique reference string for objects."""
        now = datetime.now()
        # Format: YYMMDDHHmmSS-xxxxxxxxxxxx (12 hex chars from UUID)
        ref_date = now.strftime("%y%m%d%H%M%S")
        formatted_uuid = uuid.uuid4().hex[:12]
        return f"{ref_date}-{formatted_uuid}"

    #################################### Inbox emails ####################################

    # --- Helper method to parse common email content ---
    def _parse_email_data(
        self,
        msg: email.message.EmailMessage,
        base_path_for_attachments: str,
        source_ref_for_attachments: str,
    ) -> MailboxParsedEmailData:
        """
        Extracts common fields, attachments, body, and headers from an email message.
        Attachments are saved relative to base_path_for_attachments.
        """
        data_to = self.process_recipients_field(msg.get("To"))
        data_cc = self.process_recipients_field(msg.get("Cc"))
        data_bcc = self.process_recipients_field(msg.get("Bcc"))

        data_date = msg.get("Date")
        if data_date is not None:
            data_date = self.process_date_field(data_date)

        # Decode potentially encoded headers like Subject and From
        data_subject = msg.get("Subject")
        if data_subject is not None:
            data_subject = self.process_subject_field(
                self._decode_header_str(data_subject)
            )

        data_from_header_raw = msg.get("From")
        data_from_address = None
        if data_from_header_raw:
            from_decoded = self._decode_header_str(data_from_header_raw)
            data_from_address = email.utils.parseaddr(from_decoded)[1]

        data_attachments = self.extract_attachments(
            msg, base_path_for_attachments, source_ref_for_attachments
        )

        if not os.listdir(base_path_for_attachments):
            logger.warning(
                f"Removing empty attachments directory: {base_path_for_attachments}"
            )
            shutil.rmtree(base_path_for_attachments, ignore_errors=True)
        text_body_raw, html_body_raw = self.extract_body(msg)
        data_body_text = self.process_body(text_body_raw)
        data_body_html = html_body_raw

        raw_eml_bytes = msg.as_bytes()
        header_separator = b"\r\n\r\n" if b"\r\n\r\n" in raw_eml_bytes else b"\n\n"
        try:
            raw_headers_block_bytes = raw_eml_bytes.split(header_separator, 1)[0]
            raw_headers_string = raw_headers_block_bytes.decode("ascii", "replace")
            data_headers_parsed = HeaderParser().parsestr(raw_headers_string)
        except Exception as e:
            logger.warning(
                f"Could not extract/parse headers for ref {source_ref_for_attachments}: {e}"
            )
            data_headers_parsed = {
                k: self._decode_header_str(v) for k, v in msg.items()
            }

        data_raw_eml_bytes = raw_eml_bytes

        return MailboxParsedEmailData(
            to=data_to,
            cc=data_cc,
            bcc=data_bcc,
            date=data_date,
            subject=data_subject,
            from_address=data_from_address,
            from_header_raw=data_from_header_raw,
            body_text=data_body_text,
            body_html=data_body_html,
            headers_parsed=data_headers_parsed,
            raw_eml_bytes=data_raw_eml_bytes,
            attachments=data_attachments,
        )

    def process_inbox_email(self, email_id: str, source_ref: str):
        if self.imap_server is None:
            raise Exception("The IMAP server is not instantiated.")

        try:
            status, email_data_list = self.imap_server.fetch(email_id, "(RFC822)")
        except Exception as e:
            logger.error(
                f"Error fetching or parsing email ID {email_id} (Ref: {source_ref}): {repr(e)}"
            )
            return None

        is_request_successful = (
            status == "OK"
            and email_data_list
            and len(email_data_list) >= 1
            and isinstance(email_data_list[0], tuple)
        )
        if not is_request_successful:
            logger.error(
                f"Failed to fetch email data for ID {email_id}. Status: {status}"
            )
            return None

        email_data_list = typing.cast(list[tuple[bytes, bytes]], email_data_list)
        msg_bytes = email_data_list[0][1]
        msg = email.message_from_bytes(msg_bytes, policy=email.policy.default)

        # TODO: 'From' should always be set, it makes no sense otherwise, thus
        # the message should be dropped and an error must be raised to simplify
        # the logic.
        from_header_raw = msg.get("From")
        if from_header_raw:
            from_decoded = self._decode_header_str(from_header_raw)
            email_from = email.utils.parseaddr(from_decoded)[1]
        else:
            email_from = None

        folder_name = f"{email_from.split('@')[0]}-submission"

        processing_root_dir = os.path.join(
            self.tmp_dir, folder_name + f"-{source_ref.split('-', maxsplit=1)[0]}"
        )
        try:
            os.makedirs(processing_root_dir, exist_ok=True)
        except OSError as e:
            logger.error(
                f"CRITICAL: Cannot create processing root directory '{processing_root_dir}': {repr(e)}"
            )
            return None
        main_eml_temp_filename = f"{folder_name}.eml"
        main_eml_temp_path = os.path.join(processing_root_dir, main_eml_temp_filename)
        try:
            with open(main_eml_temp_path, "wb") as eml_file:
                eml_file.write(msg.as_bytes())
        except IOError as e:
            logger.error(
                f"Failed to write temporary EML '{main_eml_temp_path}': {repr(e)}"
            )
            return None

        email_data = self._parse_email_data(msg, processing_root_dir, source_ref)
        logger.info(
            f"Processing email ID {email_id} (Ref: {source_ref}) with subject: {email_data['subject']}"
        )
        logger.debug(f"Attachments found: {len(email_data['attachments'])}")
        for att in email_data["attachments"]:
            if att.get("file_path"):
                logger.debug(
                    f"Attachment '{att['filename']}' saved at: {att['file_path']}"
                )
            else:
                logger.debug(f"Attachment '{att['filename']}' has no file path.")
        eml_attachments_in_main = [
            att
            for att in email_data["attachments"]
            if att.get("filename", "").lower().endswith(".eml")
        ]

        if eml_attachments_in_main:
            logger.info(
                f"Email Ref {source_ref} (ID: {email_id}) has .eml attachments. "
                f"Returning for recursive processing."
            )
            return [eml_attachments_in_main, processing_root_dir, source_ref]

        analysis_target_dir = os.path.join(
            processing_root_dir, f"{ANALYSIS_DIR_PREFIX}0"
        )
        try:
            os.makedirs(analysis_target_dir, exist_ok=True)
        except OSError as e:
            logger.error(
                f"Failed to create analysis directory '{analysis_target_dir}': {repr(e)}"
            )
            return None

        final_main_eml_path = os.path.join(analysis_target_dir, f"{source_ref}.eml")

        temp_attachments_dir = os.path.join(processing_root_dir, ATTACHMENTS_DIR_NAME)
        final_attachments_dir = os.path.join(analysis_target_dir, ATTACHMENTS_DIR_NAME)

        try:
            shutil.move(main_eml_temp_path, final_main_eml_path)

            updated_attachments_list = []
            if os.path.isdir(temp_attachments_dir):
                for att_dict in email_data["attachments"]:
                    original_att_path = att_dict.get("file_path")
                    if original_att_path:
                        att_filename = os.path.basename(original_att_path)
                        att_dict["file_path"] = os.path.join(
                            final_attachments_dir, att_filename
                        )
                    updated_attachments_list.append(att_dict)
                shutil.move(temp_attachments_dir, final_attachments_dir)
            elif os.path.exists(temp_attachments_dir):
                logger.warning(
                    f"Expected directory at '{temp_attachments_dir}', but found a file."
                )
            else:
                os.makedirs(final_attachments_dir, exist_ok=True)

            email_data["attachments"] = updated_attachments_list

        except (IOError, OSError) as e:
            logger.error(
                f"Error moving files from '{processing_root_dir}' to '{analysis_target_dir}': {repr(e)}"
            )
            return None

        self._save_email_files(
            path=analysis_target_dir,
            ref=source_ref,
            body=email_data["body_text"],
            body_html=email_data["body_html"],
            headers=email_data["headers_parsed"],
            eml_content=None,
        )

        return Mail(
            email_data["from_address"],
            email_data["to"],
            email_data["bcc"],
            email_data["date"],
            email_data["body_text"],
            email_data["headers_parsed"],
            email_data["subject"],
            email_data["cc"],
            email_data["attachments"],
            email_data["raw_eml_bytes"],
            email_data["body_html"],
            source_ref,
            analysis_target_dir,
            "to_resend",
        )

    def process_attachment_email(
        self,
        msg: email.message.EmailMessage,
        parent_dir_for_analysis: str,
        source_ref: str,
    ):
        attached_email_file_ref = (
            str(source_ref.split("-", maxsplit=1)[0])
            + "-"
            + str(self.generate_object_reference().split("-", maxsplit=1)[1])
        )

        analysis_dir_name = attached_email_file_ref
        current_analysis_path = os.path.join(parent_dir_for_analysis, analysis_dir_name)
        try:
            os.makedirs(current_analysis_path, exist_ok=True)
        except OSError as e:
            logger.error(
                f"Failed to create analysis directory '{current_analysis_path}': {repr(e)}"
            )
            return None

        email_data = self._parse_email_data(
            msg, current_analysis_path, attached_email_file_ref
        )

        self._save_email_files(
            path=current_analysis_path,
            ref=attached_email_file_ref,
            body=email_data["body_text"],
            body_html=email_data["body_html"],
            headers=email_data["headers_parsed"],
            eml_content=email_data["raw_eml_bytes"],
        )

        return Mail(
            email_data["from_address"],
            email_data["to"],
            email_data["bcc"],
            email_data["date"],
            email_data["body_text"],
            email_data["headers_parsed"],
            email_data["subject"],
            email_data["cc"],
            email_data["attachments"],
            email_data["raw_eml_bytes"],
            email_data["body_html"],
            attached_email_file_ref,
            current_analysis_path,
        )

    def _save_email_files(
        self,
        path: str,
        ref: str,
        body: str,
        body_html: str,
        headers,
        eml_content: bytes = None,
    ):
        """Saves derived email content (body, html, headers) and optionally the EML itself."""
        try:
            os.makedirs(path, exist_ok=True)

            if eml_content:
                with open(os.path.join(path, f"{ref}.eml"), "wb") as f:
                    f.write(eml_content)

            html_to_write = body_html if body_html is not None else ""
            with open(
                os.path.join(path, f"{ref}.html"),
                "w",
                encoding="utf-8",
                errors="replace",
            ) as f:
                f.write(html_to_write)

            text_to_write = body if body is not None else ""
            with open(
                os.path.join(path, f"{ref}.txt"),
                "w",
                encoding="utf-8",
                errors="replace",
            ) as f:
                f.write(text_to_write)

            headers_to_write = str(headers) if headers is not None else ""
            with open(
                os.path.join(path, f"{ref}.headers"),
                "w",
                encoding="utf-8",
                errors="replace",
            ) as f:
                f.write(headers_to_write)
        except IOError as e:
            logger.error(f"IOError saving files in '{path}' for ref '{ref}': {repr(e)}")
        except Exception as e:
            logger.error(
                f"Unexpected error saving files in '{path}' for ref '{ref}': {repr(e)}"
            )

    #################################### Email processing ####################################

    def extract_body(self, msg: EmailMessage) -> typing.Tuple[str, str]:
        """
        Extrait le corps plain-text et HTML.
        - Préfère 'plain', puis 'html' pour plain-text.
        - Si encodé en bytes, détecte et décode avec chardet.
        - En cas d'email chiffré, retourne un placeholder.
        """
        part_plain = msg.get_body(preferencelist=("plain"))
        part_html = msg.get_body(preferencelist=("html"))

        def _get_content(
            part: typing.Optional[EmailMessage],
        ) -> typing.Optional[bytes | str]:
            if part is None:
                return None
            payload = part.get_payload(decode=True)
            return payload if payload is not None else part.get_payload()

        raw_plain = _get_content(part_plain)
        raw_html = _get_content(part_html)

        def _to_str(raw: bytes | str | None) -> typing.Optional[str]:
            if raw is None:
                return None
            if isinstance(raw, bytes):
                enc = chardet.detect(raw)["encoding"] or "utf-8"
                try:
                    return raw.decode(enc)
                except UnicodeDecodeError:
                    logger.warning("Échec décodage (%s)", enc)
                    return raw.decode("utf-8", errors="replace")
            return raw

        body_plain = _to_str(raw_plain)
        body_html = _to_str(raw_html)

        if not body_plain and body_html:
            body_plain = BeautifulSoup(body_html, "html.parser").get_text()
        if not body_html and body_plain:
            body_html = body_plain

        ctype = msg.get_content_type()
        if ctype in {"application/pkcs7-mime", "multipart/encrypted"} or (
            body_plain is None and body_html is None
        ):
            placeholder = "Encrypted email"
            return placeholder, placeholder

        return body_plain or "", body_html or ""

    def process_recipients_field(self, raw: typing.Optional[str]) -> list[str]:
        """
        Sépare et normalise la liste d'adresses.
        Gère les formats 'Nom <mail>' et les virgules internes via getaddresses :contentReference[oaicite:8]{index=8}.
        """
        if not raw:
            return []
        return [addr for _, addr in email.utils.getaddresses([raw])]

    def process_date_field(self, raw: str) -> typing.Optional[str]:
        """
        Parse une date libre et la convertit en Europe/Paris.
        Format de sortie : 'lundi 1 janvier 2025 13:45:00'.
        """
        try:
            dt = parser.parse(raw)
            paris = tz.gettz("Europe/Paris")
            dt = dt.astimezone(paris)
            return dt.strftime("%A %-d %B %Y %H:%M:%S")
        except (ValueError, TypeError) as e:
            logger.error("Date invalide '%s' : %s", raw, e)
            return None

    def process_subject_field(self, raw: typing.Optional[str]) -> typing.Optional[str]:
        """
        Décodage RFC2047 du sujet.
        Nettoie retours chariot superflus.
        """
        if raw is None:
            return None
        subj, enc = email.header.decode_header(raw)[0]
        if isinstance(subj, bytes):
            subj = subj.decode(enc or "utf-8", errors="replace")
        return subj.replace("\r", "").replace("\n", "")

    def process_body(self, text: str) -> str:
        """
        Nettoie le corps :
        - Supprime espaces NBSP, retours chariot inutiles, cid:, balises de classification.
        - Regroupe plus de 2 sauts de ligne en 2.
        """
        patterns = [
            (r"\u00A0|\r", ""),
            (r" +\n", "\n"),
            (r"=\n", ""),
            (r"\[cid:.*?\]\n?", ""),
            (r"Sensitivity:.*\n", ""),
            (r"Critère de diffusion ?:.*\n", ""),
            (r"\n{3,}", "\n\n"),
            (r"((From|De).*)\n\n", r"\1\n"),
            (r"^\s+|\s+$", ""),
        ]
        for pat, repl in patterns:
            text = re.sub(pat, repl, text, flags=re.MULTILINE)
        return text

    def get_sha256(self, file_path: str) -> typing.Optional[str]:
        """
        Calcule le SHA‑256 en lecture par blocs (8 KiB).
        Limite mémoire pour gros fichiers :contentReference[oaicite:9]{index=9}.
        """
        try:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            logger.error("Fichier introuvable : %s", file_path)
            return None

    def _decode_header_str(self, header_value: str) -> str:
        """Safely decodes email header values."""
        if not header_value:
            return ""
        parts = []
        for decoded_bytes, charset in email.header.decode_header(str(header_value)):
            if isinstance(decoded_bytes, bytes):
                try:
                    parts.append(
                        decoded_bytes.decode(charset or "utf-8", errors="replace")
                    )
                except LookupError:
                    parts.append(decoded_bytes.decode("latin-1", errors="replace"))
            else:
                parts.append(decoded_bytes)
        return "".join(parts)

    def _sanitize_filename(
        self, filename: str, id_num: int, default_base: str = "attachment"
    ) -> str:
        """Sanitizes a filename to be safe for file systems and limits its length."""
        if not filename.strip():
            filename = f"{default_base}_{id_num}"

        sanitized = re.sub(r"[^\w\s.-]", "_", filename)
        sanitized = re.sub(r"[\s_]+", "_", sanitized).strip("_")

        if not sanitized:
            sanitized = f"{default_base}_{id_num}"

        name_part, ext_part = os.path.splitext(sanitized)
        max_name_len = 200 - len(ext_part)
        return name_part[:max_name_len] + ext_part

    def get_header_dict_list(self, msg: email.message.EmailMessage):
        headers: dict[str, list[typing.Any]] = {}
        for key, value in msg.items():
            if key not in headers:
                headers[key] = [value]
            else:
                headers[key].append(value)
        return headers

    def extract_attachments(
        self, msg: email.message.EmailMessage, tmp_path: str, source_ref: str
    ) -> list[Attachment]:
        attachments: list[Attachment] = []

        attachments_output_dir = os.path.join(tmp_path, "attachments")
        try:
            os.makedirs(attachments_output_dir, exist_ok=True)
        except OSError as e:
            logger.error(
                f"Failed to create attachments directory '{attachments_output_dir}'. Error: {repr(e)}"
            )
            return attachments

        for i, part in enumerate(msg.iter_attachments()):
            original_filename = part.get_filename()
            logger.debug(
                f"Processing attachment {i + 1}: '{original_filename}' (Content-Type: {part.get_content_type()})"
            )
            content_type = part.get_content_type()
            processed_filename = ""

            # --- Skip detached signatures ---
            if content_type in {
                "application/pgp-signature",
                "application/pkcs7-signature",
            }:
                logger.info(
                    f"Skipping detached signature part of type '{content_type}'."
                )
                continue

            # --- 1. Determine Filename ---
            if original_filename:
                decoded_original_filename = self._decode_header_str(original_filename)
                processed_filename = self._sanitize_filename(
                    decoded_original_filename, i
                )
            elif content_type == "message/rfc822":
                default_eml_name = f"embedded_email_{i}"
                subject = default_eml_name

                embedded_msg_payload = part.get_payload()
                actual_embedded_msg = None
                if isinstance(embedded_msg_payload, list) and embedded_msg_payload:
                    if isinstance(embedded_msg_payload[0], email.message.EmailMessage):
                        actual_embedded_msg = embedded_msg_payload[0]
                elif isinstance(embedded_msg_payload, email.message.EmailMessage):
                    actual_embedded_msg = embedded_msg_payload

                if actual_embedded_msg:
                    embedded_subject = self._decode_header_str(
                        actual_embedded_msg.get("Subject")
                    )
                    if embedded_subject.strip():
                        subject = embedded_subject

                processed_filename = (
                    self._sanitize_filename(subject, i, default_base="embedded_email")
                    + ".eml"
                )
            else:
                extension = mimetypes.guess_extension(content_type) or ".dat"
                base_name = f"attachment_{i}"
                processed_filename = self._sanitize_filename(base_name, i) + extension

            file_path = os.path.join(attachments_output_dir, processed_filename)

            # --- 2. Get Attachment Data and Write to File ---
            try:
                attachment_bytes: bytes | None = None
                if content_type == "message/rfc822":
                    payload_to_write = part.get_payload()
                    msg_to_write = None
                    if isinstance(payload_to_write, list) and payload_to_write:
                        msg_to_write = (
                            payload_to_write[0]
                            if isinstance(
                                payload_to_write[0], email.message.EmailMessage
                            )
                            else None
                        )
                    elif isinstance(payload_to_write, email.message.EmailMessage):
                        msg_to_write = payload_to_write

                    if msg_to_write:
                        attachment_bytes = msg_to_write.as_bytes()
                    else:
                        logger.warning(
                            f"Content of '{processed_filename}' (message/rfc822) not a standard EmailMessage. Saving raw part data."
                        )
                        raw_payload = part.get_payload(decode=True)
                        if isinstance(raw_payload, str):
                            attachment_bytes = raw_payload.encode(
                                part.get_content_charset() or "utf-8", "replace"
                            )
                        elif isinstance(raw_payload, bytes):
                            attachment_bytes = raw_payload
                        else:
                            attachment_bytes = part.as_bytes()

                else:
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        logger.warning(
                            f"Attachment '{processed_filename}' has no decodable payload. Skipping."
                        )
                        continue
                    if isinstance(payload, str):
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            attachment_bytes = payload.encode(charset, "replace")
                        except LookupError:
                            attachment_bytes = payload.encode("utf-8", "replace")
                    elif isinstance(payload, bytes):
                        attachment_bytes = payload
                    else:
                        logger.warning(
                            f"Attachment '{processed_filename}' has unexpected payload type: {type(payload)}. Saving raw part data."
                        )
                        attachment_bytes = part.as_bytes()

                if attachment_bytes is None:
                    logger.warning(
                        f"Could not extract data for attachment '{processed_filename}'. Skipping."
                    )
                    continue

                counter = 1
                temp_filepath = file_path
                base_fp, ext_fp = os.path.splitext(file_path)
                while os.path.exists(temp_filepath):
                    temp_filepath = f"{base_fp}_{counter}{ext_fp}"
                    counter += 1
                file_path = temp_filepath
                processed_filename = os.path.basename(file_path)

                with open(file_path, "wb") as att_file:
                    att_file.write(attachment_bytes)

                file_sha256 = self.get_sha256(file_path)

                attachment_details = Attachment(
                    filename=processed_filename,
                    content=attachment_bytes,
                    headers=self.get_header_dict_list(part),
                    file_path=file_path,
                    file_sha256=file_sha256,
                    parent=source_ref,
                )
                attachments.append(attachment_details)

            except Exception as e:
                logger.error(
                    f"Error while trying to get attachment data for '{processed_filename}' and writing as file. Error: {repr(e)}"
                )
                continue

        return attachments
