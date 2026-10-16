import ast
import json
import os
import logging
import hashlib
from django.db.models import F
from django.db import transaction
from file_process.models import File, HashFromFile
from hash_process.models import Hash

logger = logging.getLogger(__name__)

# File.other_names is a small alias list (the other names a file was reported
# under). Bound it: it is rewritten on every re-submission of the same file.
MAX_OTHER_NAMES = 100
MAX_OTHER_NAMES_CHARS = 8192  # a longer value is corrupt, never a real list


def parse_other_names(raw) -> list[str]:
    """Read File.other_names into a clean, de-duplicated list of names.

    Reads the JSON written by ``format_other_names`` and the ``str(list)`` form
    older versions wrote. The older code re-split that text on commas, which
    wrapped every name in one more layer of quotes and escapes per update, so a
    file reported again under another name doubled its ``other_names`` each
    time until a single UPDATE passed MariaDB's ``max_allowed_packet``. Those
    damaged values are cleaned up here, or dropped when beyond repair.
    """
    if not raw or not isinstance(raw, str) or len(raw) > MAX_OTHER_NAMES_CHARS:
        return []
    try:
        values = ast.literal_eval(raw)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return []
    if not isinstance(values, (list, tuple)):
        return []
    names: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        name = value.strip("'\"\\ ")
        if name and len(name) <= 255 and name not in names:
            names.append(name)
    return names[:MAX_OTHER_NAMES]


def format_other_names(names: list[str]) -> str:
    return json.dumps(names, ensure_ascii=False) if names else ""


class FileHandler:

    @classmethod
    def handle_file(cls, file=None, mail=None):
        """
        Handle a file (or mail-based file path) and create or update a File instance
        along with its associated Hash instance.

        Args:
            file: A file-like object (must implement .name and .temporary_file_path()).
            mail: A string representing a mail file path.

        Returns:
            tuple: (file_instance, hash_instance) if successful, otherwise (None, None).
        """
        if not file and not mail:
            logger.error("No file or mail provided.")
            return None, None

        file_path, tmp_path, hash_value = None, None, None

        if file:
            file_path = file.name
            tmp_path_raw = file.temporary_file_path()
            tmp_path = tmp_path_raw.replace("/tmp/", "")
            hash_value = cls.hash_file(tmp_path_raw)
        elif mail:
            file_path = os.path.basename(mail)
            tmp_path = mail
            tmp_path_raw = mail
            hash_value = cls.hash_file(tmp_path_raw)

        if not hash_value:
            logger.error("Failed to compute hash for file: %s", file_path)
            return None, None

        handler = cls()
        return handler._handle_file_logic(file_path, tmp_path, hash_value, tmp_path_raw)

    def _handle_file_logic(self, file_path: str, tmp_path: str, hash_value: str, tmp_path_raw: str):
        """
        Process the file by checking its size, ensuring a Hash instance exists,
        and then creating or updating the associated File instance.

        Args:
            file_path (str): The original file name.
            tmp_path (str): The temporary file path, stored on the File model.
                Convention is inconsistent by caller (stripped of a leading
                "/tmp/" for the `file` branch, left absolute for the `mail`
                branch; downstream code in mail_feeder/job_handler strips
                and re-prefixes it at its own pace) so it must NOT be used to
                locate the file on disk here.
            hash_value (str): The SHA-256 hash of the file.
            tmp_path_raw (str): The real, directly-openable absolute path,
                the same path `hash_file()` already read the bytes from.

        Returns:
            tuple: (file_instance, hash_instance).
        """
        try:
            size = os.path.getsize(tmp_path_raw)
        except FileNotFoundError:
            logger.error("Temporary file not found at: %s", tmp_path_raw)
            size = 0

        with transaction.atomic():
            hash_instance, created = Hash.objects.get_or_create(
                value=hash_value,
                defaults={"hashtype": "SHA-256"}
            )
            if not created:
                hash_instance.times_sent = F('times_sent') + 1
                hash_instance.save()

            file_instance = File.objects.filter(linked_hash=hash_instance).first()

            if file_instance:
                file_instance = self._update_existing_file_instance(file_instance, file_path, tmp_path, size)
            else:
                file_instance = self._create_new_file_instance(file_path, tmp_path, hash_instance, size)

        return file_instance, hash_instance

    def _create_new_file_instance(self, file_path: str, tmp_path: str, hash_instance: Hash, size: int):
        """
        Create and save a new File instance along with its HashFromFile relation.

        Args:
            file_path (str): The original file name.
            tmp_path (str): The temporary file path.
            hash_instance (Hash): The associated Hash instance.
            size (int): The file size in bytes.

        Returns:
            File: The newly created File instance.
        """
        try:
            filetype = tmp_path.split('.')[-1] if '.' in tmp_path else 'unknown'
            file_instance = File.objects.create(
                linked_hash=hash_instance,
                file_path=file_path,
                tmp_path=tmp_path,
                filetype=filetype,
                size=size
            )
            HashFromFile.objects.create(
                hash=hash_instance,
                file=file_instance
            )
            logger.info("Created new file instance for %s", file_path)
            return file_instance
        except Exception as e:
            logger.error("Error creating new file instance for '%s': %s", file_path, str(e))
            raise

    def _update_existing_file_instance(self, file_instance, file_path: str, tmp_path: str, size: int):
        """
        Update an existing File instance with new details.

        Args:
            file_instance (File): The existing File instance.
            file_path (str): The new file name.
            tmp_path (str): The updated temporary file path.
            size (int): The file size in bytes.

        Returns:
            File: The updated File instance.
        """
        try:
            existing_name = file_instance.file_path
            if hasattr(existing_name, 'name'):
                existing_name = existing_name.name

            raw_names = file_instance.other_names
            names = parse_other_names(raw_names)
            alias = str(file_path) if file_path else ""
            if (
                alias
                and existing_name != file_path
                and alias not in names
                and len(names) < MAX_OTHER_NAMES
            ):
                names.append(alias)
            other_names = format_other_names(names)

            file_instance.tmp_path = tmp_path
            file_instance.size = size
            file_instance.times_sent = F('times_sent') + 1
            # Write only what changed: save() would otherwise send every column,
            # including an unchanged (possibly huge, legacy) other_names.
            update_fields = ["tmp_path", "size", "times_sent", "last_update"]
            if other_names != (raw_names or ""):
                file_instance.other_names = other_names
                update_fields.append("other_names")
            file_instance.save(update_fields=update_fields)
            logger.info("Updated file instance for %s", file_path)
            return file_instance
        except Exception as e:
            logger.error("Error updating file instance for '%s': %s", file_path, str(e))
            raise

    @staticmethod
    def hash_file(file_path: str) -> str | None:
        """
        Calculate the SHA-256 hash of a file.

        Args:
            file_path (str): The path to the file.

        Returns:
            str: The hexadecimal SHA-256 digest of the file,
                 or None if the file is not found.
        """
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256()
                for chunk in iter(lambda: f.read(8192), b""):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except FileNotFoundError:
            logger.error("File not found: %s", file_path)
            return None
