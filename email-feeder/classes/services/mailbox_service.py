import chardet
import datetime
import dateutil
import email
import email.utils
import email.message
import email.header
import email.policy
import email.parser
import hashlib
import logging
import mimetypes
import os
import pathlib
import re
import shutil
import typing
import uuid

import bs4

import classes.models.mail
import classes.models.mail_attachment
import classes.models.mail_exceptions
import classes.models.configs.internals.imap
import classes.services.mail_client_service as mail_client_service


# --- Configuration & Constants ---
MAILBOX_LOGGER_NAME = "email-feeder.mailbox"
ATTACHMENTS_DIR_NAME = "attachments"
ANALYSIS_DIR_PREFIX = "analysis_"


class Mailbox:
    fetched_unseen_email_ids: list[str] = []

    def __init__(
        self,
        config: classes.models.configs.internals.imap.IMAPConfig,
        logger: logging.Logger,
        tmp_path: pathlib.Path,
    ):
        self.__config = config

        self.__logger = logger

        self.__tmp_path = tmp_path

        self.__mail_client = mail_client_service.MailClient(
            config=config,
            logger=self.__logger,
        )

    @property
    def config(self) -> classes.models.configs.internals.imap.IMAPConfig:
        return self.__config

    # --- Connection Management (Context Manager) ---
    def __enter__(self):
        """Enters the runtime context related to this object, calls login."""
        self.login()
        return self

    def login(self):
        self.__mail_client.login()

    def __exit__(self):
        """Exits the runtime context, calls logout."""
        self.logout()

    def logout(self):
        return self.__mail_client.logout()

    # --- Email Operations ---
    def mark_emails_as_seen(self, email_ids: typing.Sequence[str | bytes]):
        """Marks the specified email IDs (or cached fetched unseen emails) as seen."""
        if len(email_ids) == 0:
            self.__logger.warning("No email IDs to mark as seen.")
            return

        # Ensure IDs are byte strings for joining, as received from search()
        encoded_email_ids = [
            eid.encode() if isinstance(eid, str) else eid for eid in email_ids
        ]
        email_ids_query = b",".join(encoded_email_ids)
        self.__logger.info(
            f"Marking {len(email_ids_query)} emails as seen in '{self.__config.mailbox_to_monitor}'."
        )

        # Prepare the UTF-8 decoded email ids query
        try:
            decoded_email_ids_query = email_ids_query.decode("utf-8")
        except OSError as e:
            error_msg = (
                f"Error marking emails as seen in {self.__config.mailbox_to_monitor} "
                f"for {self.__config.login}: {repr(e)}"
            )
            self.__logger.error(error_msg)
            raise classes.models.mail_exceptions.MailboxOperationError(error_msg) from e

        # Try to mark the emails as 'SEEN'.
        try:
            self.__mail_client.mark_email_as_seen(decoded_email_ids_query)
        except classes.models.mail_exceptions.MailboxOperationError as e:
            self.__logger.error(e)
            raise e

        self.__logger.info(
            f"Successfully marked emails as seen: {decoded_email_ids_query}"
        )

    def search_mails(self, charset: str | None, *criteria: str) -> list[bytes]:
        """Search mails matching the given criteria in the selected mailbox.

        Parameters
        ----------
        charset : str | None
            If UTF8 is enabled, charset MUST be None.

        *criteria : str
            The criteria used when searching for mails.

        Returns
        -------
        list[str]
            The list of matching mail IDs.

        Raises
        ------
        MailboxConnectionError
            If the IMAP server is not instantiated before calling this method.
        classes.models.mail_exceptions.MailboxOperationError
            If the mailbox search command failed.
        """
        # Search for unseen emails. Consider using UID SEARCH for UIDs if preferred over sequence numbers.
        _, response = self.__mail_client.search(charset, *criteria)

        # Check if there is no new email, or if it's whitespace-only
        if len(response) > 0 and len(response[0].strip()) > 0:
            # email_ids are space-separated bytes string of message numbers
            encoded_email_ids: list[bytes] = response[0].split()

            return encoded_email_ids

        self.__logger.info(
            f"No unseen emails found in '{self.__config.mailbox_to_monitor}' for {self.__config.login}."
        )
        return []

    def fetch_unseen_email_ids(self) -> list[bytes]:
        # Try to fetch all the UNSEED mail IDs.
        mailbox = self.__config.mailbox_to_monitor
        try:
            self.__mail_client.select(mailbox=mailbox, readonly=False)

            fetched_unseen_email_ids = self.search_mails(None, "(UNSEEN)")
        except OSError as e:
            error_msg = (
                f"Error during email search in {mailbox} "
                f"for {self.__config.login}: {repr(e)}"
            )
            self.__logger.error(error_msg)
            raise classes.models.mail_exceptions.MailboxOperationError(error_msg) from e

        self.__logger.info(
            f"Found {len(fetched_unseen_email_ids)} unseen emails in "
            f"'{mailbox}' for {self.__config.login}."
        )

        return fetched_unseen_email_ids

    def process_unseen_email(
        self, email_id: bytes
    ) -> list[classes.models.mail.SuspiciousMailResponse]:
        source_ref = self.generate_object_reference()

        processed_email = self.process_inbox_email(email_id, source_ref)
        if processed_email is None:
            return []

        if isinstance(processed_email, classes.models.mail.SuspiciousMailResponse):
            return [processed_email]

        processed_emails: list[classes.models.mail.SuspiciousMailResponse] = []
        eml_attachments, base_tmp_path, main_email_source_ref = processed_email
        for attachment in eml_attachments:
            eml_file_path = (
                pathlib.Path(attachment.file_path)
                if attachment.file_path is not None
                else None
            )

            if eml_file_path is None or not eml_file_path.exists():
                self.__logger.error(
                    f"EML attachment file not found or path missing: "
                    f"'{attachment.filename}' from ref {main_email_source_ref}"
                )
                continue

            try:
                with open(eml_file_path, "rb") as f_eml:
                    attached_msg = email.message_from_binary_file(
                        f_eml, policy=email.policy.default
                    )
            except Exception as e:
                self.__logger.error(
                    f"Failed to process EML attachment "
                    f"'{attachment.filename}': {repr(e)}"
                )
            else:
                processed_attached_mail_obj = self.process_attachment_email(
                    email_id=email_id,
                    msg=attached_msg,
                    parent_dir_for_analysis=base_tmp_path,
                    source_ref=main_email_source_ref,
                )
                if processed_attached_mail_obj:
                    processed_emails.append(processed_attached_mail_obj)

        return processed_emails

    def process_unseen_emails(self, email_ids: list[bytes]):
        processed_emails: list[classes.models.mail.SuspiciousMailResponse] = []

        # Process each fetched email ID
        for email_id in email_ids:
            try:
                _processed_mails = self.process_unseen_email(email_id)
            except Exception as e:
                self.__logger.error(
                    f"An unexpected error occured while processing email with ID {email_id}.\n{repr(e)}"
                )
                continue
            else:
                processed_emails.extend(_processed_mails)

        return processed_emails

    def fetch_unseen_emails_and_process(
        self,
    ) -> list[classes.models.mail.SuspiciousMailResponse]:
        email_ids = self.fetch_unseen_email_ids()

        processed_emails = self.process_unseen_emails(email_ids=email_ids)

        return processed_emails

    # --- Utility ---
    def generate_object_reference(self):
        """Generates a more unique reference string for objects."""
        now = datetime.datetime.now()
        # Format: YYMMDDHHmmSS-xxxxxxxxxxxx (12 hex chars from UUID)
        ref_date = now.strftime("%y%m%d%H%M%S")
        formatted_uuid = uuid.uuid4().hex[:12]
        return f"{ref_date}-{formatted_uuid}"

    #################################### Inbox emails ####################################

    # --- Helper method to parse common email content ---
    def _parse_email_data(
        self,
        id: bytes,
        msg: email.message.EmailMessage,
        base_path_for_attachments: pathlib.Path,
        source_ref_for_attachments: str,
    ) -> classes.models.mail.SuspiciousMailRequest:
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
            self.__logger.warning(
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
            data_headers_parsed = email.parser.HeaderParser().parsestr(
                raw_headers_string
            )
        except Exception as e:
            self.__logger.warning(
                f"Could not extract/parse headers for ref {source_ref_for_attachments}: {e}"
            )
            data_headers_parsed = {
                k: self._decode_header_str(v) for k, v in msg.items()
            }

        data_raw_eml_bytes = raw_eml_bytes

        return classes.models.mail.SuspiciousMailRequest(
            id=id,
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

    def process_inbox_email(
        self, email_id: bytes, source_ref: str
    ) -> (
        tuple[list[classes.models.mail_attachment.MailAttachment], pathlib.Path, str]
        | classes.models.mail.SuspiciousMailResponse
        | None
    ):
        try:
            _, response = self.__mail_client.fetch(
                email_id=email_id, message_parts="(RFC822)"
            )
        except classes.models.mail_exceptions.MailboxOperationError as e:
            self.__logger.error(e)
            return None

        response = typing.cast(list[tuple[bytes, bytes]], response)
        msg_bytes = response[0][1]
        msg = email.message_from_bytes(msg_bytes, policy=email.policy.default)

        from_header_raw = msg.get("From")
        if from_header_raw is None:
            self.__logger.warning(
                f"The mail with ID {email_id} has no 'From' header. Skipped."
            )
            return None

        from_decoded = self._decode_header_str(from_header_raw)
        email_from = email.utils.parseaddr(from_decoded)[1]
        folder_name = f"{email_from.split('@')[0]}-submission"

        processing_root_dir = pathlib.Path(
            self.__tmp_path, folder_name + f"-{source_ref.split('-', maxsplit=1)[0]}"
        )
        try:
            processing_root_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.__logger.error(
                f"CRITICAL: Cannot create processing root directory '{processing_root_dir}': {repr(e)}"
            )
            return None

        main_eml_temp_filename = f"{folder_name}.eml"
        main_eml_temp_path = pathlib.Path(processing_root_dir, main_eml_temp_filename)
        try:
            main_eml_temp_path.write_bytes(msg.as_bytes())
        except IOError as e:
            self.__logger.error(
                f"Failed to write temporary EML '{main_eml_temp_path}': {repr(e)}"
            )
            return None

        email_data = self._parse_email_data(
            id=email_id,
            msg=msg,
            base_path_for_attachments=processing_root_dir,
            source_ref_for_attachments=source_ref,
        )
        self.__logger.info(
            f"Processing email ID {email_id} (Ref: {source_ref}) with subject: {email_data.subject}"
        )
        self.__logger.debug(f"Attachments found: {len(email_data.attachments)}")
        for att in email_data.attachments:
            if att.file_path:
                self.__logger.debug(
                    f"Attachment '{att.filename}' saved at: {att.file_path}"
                )
            else:
                self.__logger.debug(f"Attachment '{att.filename}' has no file path.")

        eml_attachments_in_main = [
            att
            for att in email_data.attachments
            if att.filename.lower().endswith(".eml")
        ]
        if len(eml_attachments_in_main) > 0:
            self.__logger.info(
                f"Email Ref {source_ref} (ID: {email_id}) has .eml attachments. "
                f"Returning for recursive processing."
            )
            return (eml_attachments_in_main, processing_root_dir, source_ref)

        analysis_target_dir = pathlib.Path(
            processing_root_dir, f"{ANALYSIS_DIR_PREFIX}0"
        )
        try:
            analysis_target_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.__logger.error(
                f"Failed to create analysis directory '{analysis_target_dir}': {repr(e)}"
            )
            return None

        final_main_eml_path = pathlib.Path(analysis_target_dir, f"{source_ref}.eml")

        temp_attachments_dir = pathlib.Path(processing_root_dir, ATTACHMENTS_DIR_NAME)
        final_attachments_dir = pathlib.Path(analysis_target_dir, ATTACHMENTS_DIR_NAME)

        updated_attachments_list: list[
            classes.models.mail_attachment.MailAttachment
        ] = []
        try:
            shutil.move(main_eml_temp_path, final_main_eml_path)

            if temp_attachments_dir.is_dir():
                for att_dict in email_data.attachments:
                    original_att_path = att_dict.file_path
                    if original_att_path is not None:
                        att_path = pathlib.Path(original_att_path)
                        att_dict.file_path = str(
                            pathlib.Path(final_attachments_dir, att_path.name)
                        )
                    updated_attachments_list.append(att_dict)
                shutil.move(temp_attachments_dir, final_attachments_dir)
            elif temp_attachments_dir.exists():
                self.__logger.warning(
                    f"Expected directory at '{temp_attachments_dir}', but found a file."
                )
            else:
                final_attachments_dir.mkdir(parents=True, exist_ok=True)

            email_data.attachments = updated_attachments_list

        except (IOError, OSError) as e:
            self.__logger.error(
                f"Error moving files from '{processing_root_dir}' to '{analysis_target_dir}': {repr(e)}"
            )
            return None

        self._save_email_files(
            path=analysis_target_dir,
            ref=source_ref,
            body=email_data.body_text,
            body_html=email_data.body_html,
            headers=email_data.headers_parsed,
            eml_content=None,
        )

        return classes.models.mail.SuspiciousMailResponse(
            original_mail=email_data,
            id=source_ref,
            case_path=str(analysis_target_dir),
            tags="to_resend",
        )

    def process_attachment_email(
        self,
        email_id: bytes,
        msg: email.message.EmailMessage,
        parent_dir_for_analysis: pathlib.Path,
        source_ref: str,
    ):
        attached_email_file_ref = (
            str(source_ref.split("-", maxsplit=1)[0])
            + "-"
            + str(self.generate_object_reference().split("-", maxsplit=1)[1])
        )

        analysis_dir_name = attached_email_file_ref
        current_analysis_path = pathlib.Path(parent_dir_for_analysis, analysis_dir_name)
        try:
            current_analysis_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.__logger.error(
                f"Failed to create analysis directory '{current_analysis_path}': {repr(e)}"
            )
            return None

        email_data = self._parse_email_data(
            id=email_id,
            msg=msg,
            base_path_for_attachments=current_analysis_path,
            source_ref_for_attachments=attached_email_file_ref,
        )

        self._save_email_files(
            path=current_analysis_path,
            ref=attached_email_file_ref,
            body=email_data.body_text,
            body_html=email_data.body_html,
            headers=email_data.headers_parsed,
            eml_content=email_data.raw_eml_bytes,
        )

        return classes.models.mail.SuspiciousMailResponse(
            original_mail=email_data,
            id=attached_email_file_ref,
            case_path=str(current_analysis_path),
        )

    def _save_email_files(
        self,
        path: pathlib.Path,
        ref: str,
        body: str | None = None,
        body_html: str | None = None,
        headers: email.message.Message | dict[str, str] | None = None,
        eml_content: bytes | None = None,
    ):
        """Saves derived email content (body, html, headers) and optionally the EML itself."""
        try:
            path.mkdir(parents=True, exist_ok=True)

            if eml_content is not None:
                eml_content_path = pathlib.Path(path, f"{ref}.eml")
                eml_content_path.write_bytes(eml_content)

            if body_html is not None:
                html_path = pathlib.Path(path, f"{ref}.html")
                html_path.write_text(body_html, encoding="utf-8", errors="replace")

            if body is not None:
                text_path = pathlib.Path(path, f"{ref}.txt")
                text_path.write_text(body, encoding="utf-8", errors="replace")

            if headers is not None:
                if isinstance(headers, dict):
                    headers_to_write = "\n".join(
                        [f"{k}: {v}" for k, v in headers.items()]
                    )
                else:
                    headers_to_write = headers.as_string()
                headers_path = pathlib.Path(path, f"{ref}.headers")
                headers_path.write_text(
                    headers_to_write, encoding="utf-8", errors="replace"
                )
        except IOError as e:
            self.__logger.error(
                f"IOError saving files in '{path}' for ref '{ref}': {repr(e)}"
            )
        except Exception as e:
            self.__logger.error(
                f"Unexpected error saving files in '{path}' for ref '{ref}': {repr(e)}"
            )

    #################################### Email processing ####################################

    @staticmethod
    def try_decode_bytes(
        raw: email.message.Message
        | str
        | list[email.message.Message | str]
        | bytes
        | None,
    ) -> typing.Optional[str]:
        if raw is None:
            return None

        # NOTE: this may be error prone, but do we actually expect a list of
        # emails or strings ? It's all about function's signature typing.
        if isinstance(raw, list):
            return None

        if isinstance(raw, (email.message.Message)):
            raw = raw.as_bytes()

        if isinstance(raw, (bytes, bytearray, memoryview)):
            if isinstance(raw, memoryview):
                raw = raw.tobytes()

            enc = chardet.detect(raw)["encoding"] or "utf-8"
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                return raw.decode("utf-8", errors="replace")

        return raw

    def extract_body(self, msg: email.message.EmailMessage) -> tuple[str, str]:
        """
        Extrait le corps plain-text et HTML.
        - Préfère 'plain', puis 'html' pour plain-text.
        - Si encodé en bytes, détecte et décode avec chardet.
        - En cas d'email chiffré, retourne un placeholder.
        """
        part_plain = msg.get_body(preferencelist=("plain"))
        part_html = msg.get_body(preferencelist=("html"))

        raw_plain = (
            (part_plain.get_payload(decode=True) or part_plain.get_payload())
            if part_plain
            else None
        )

        raw_html = (
            (part_html.get_payload(decode=True) or part_html.get_payload())
            if part_html
            else None
        )

        body_plain = self.try_decode_bytes(raw_plain)
        body_html = self.try_decode_bytes(raw_html)

        if body_plain is None and body_html is not None:
            body_plain = bs4.BeautifulSoup(body_html, "html.parser").get_text()
        if body_html is None and body_plain is not None:
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
            dt = dateutil.parser.parse(raw)
            paris = dateutil.tz.gettz("Europe/Paris")
            dt = dt.astimezone(paris)
            return dt.strftime("%A %-d %B %Y %H:%M:%S")
        except (ValueError, TypeError) as e:
            self.__logger.error("Date invalide '%s' : %s", raw, e)
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

    def get_sha256(self, file_path: pathlib.Path) -> typing.Optional[str]:
        """
        Calcule le SHA-256 en lecture par blocs (8 KiB).
        Limite mémoire pour gros fichiers :contentReference[oaicite:9]{index=9}.
        """
        hasher = hashlib.sha256()

        if not file_path.exists():
            self.__logger.error("Fichier introuvable : %s", file_path)
            return None

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _decode_header_str(self, header_value: str) -> str:
        """Safely decodes email header values."""
        if not header_value:
            return ""
        parts: list[str] = []
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
        self, msg: email.message.EmailMessage, tmp_path: pathlib.Path, source_ref: str
    ) -> list[classes.models.mail_attachment.MailAttachment]:
        attachments: list[classes.models.mail_attachment.MailAttachment] = []

        attachments_output_dir = pathlib.Path(tmp_path, "attachments")
        try:
            attachments_output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.__logger.error(
                f"Failed to create attachments directory '{attachments_output_dir}'. Error: {repr(e)}"
            )
            return attachments

        for i, part in enumerate(msg.iter_attachments()):
            original_filename = part.get_filename()
            self.__logger.debug(
                f"Processing attachment {i + 1}: '{original_filename}' (Content-Type: {part.get_content_type()})"
            )
            content_type = part.get_content_type()
            processed_filename = ""

            # --- Skip detached signatures ---
            if content_type in {
                "application/pgp-signature",
                "application/pkcs7-signature",
            }:
                self.__logger.info(
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
                        actual_embedded_msg.get("Subject", "")
                    )
                    if len(embedded_subject.strip()):
                        subject = embedded_subject

                processed_filename = (
                    self._sanitize_filename(subject, i, default_base="embedded_email")
                    + ".eml"
                )
            else:
                extension = mimetypes.guess_extension(content_type) or ".dat"
                base_name = f"attachment_{i}"
                processed_filename = self._sanitize_filename(base_name, i) + extension

            file_path = pathlib.Path(attachments_output_dir, processed_filename)

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
                        self.__logger.warning(
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
                        self.__logger.warning(
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
                        self.__logger.warning(
                            f"Attachment '{processed_filename}' has unexpected payload type: {type(payload)}. Saving raw part data."
                        )
                        attachment_bytes = part.as_bytes()

                counter = 1
                temp_filepath = file_path
                base_fp, ext_fp = os.path.splitext(file_path)
                while os.path.exists(temp_filepath):
                    temp_filepath = pathlib.Path(
                        *file_path.parents, f"{base_fp}_{counter}{ext_fp}"
                    )
                    counter += 1
                file_path = temp_filepath
                processed_filename = file_path.name

                file_path.write_bytes(attachment_bytes)
                file_sha256 = self.get_sha256(file_path)

                attachment_details = classes.models.mail_attachment.MailAttachment(
                    filename=processed_filename,
                    content=attachment_bytes,
                    headers=self.get_header_dict_list(part),
                    file_path=str(file_path),
                    file_sha256=file_sha256,
                    parent=source_ref,
                )
                attachments.append(attachment_details)

            except Exception as e:
                self.__logger.error(
                    f"Error while trying to get attachment data for '{processed_filename}' and writing as file. Error: {repr(e)}"
                )
                continue

        return attachments
