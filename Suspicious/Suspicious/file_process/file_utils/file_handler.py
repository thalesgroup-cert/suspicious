import os
import logging
import hashlib
from django.db.models import F
from django.db import transaction
from file_process.models import File, HashFromFile
from hash_process.models import Hash
import json
from pathlib import Path

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

suspicious_config = config.get('suspicious', {})

logger = logging.getLogger(__name__)

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
            # Remove leading '/tmp/' if present
            tmp_path = tmp_path_raw.replace("/tmp/", "")
            hash_value = cls.hash_file(tmp_path_raw)
        elif mail:
            file_path = os.path.basename(mail)
            tmp_path = mail
            hash_value = cls.hash_file(tmp_path)

        if not hash_value:
            logger.error("Failed to compute hash for file: %s", file_path)
            return None, None

        handler = cls()
        return handler._handle_file_logic(file_path, tmp_path, hash_value)

    def _handle_file_logic(self, file_path: str, tmp_path: str, hash_value: str):
        """
        Process the file by checking its size, ensuring a Hash instance exists,
        and then creating or updating the associated File instance.

        Args:
            file_path (str): The original file name.
            tmp_path (str): The temporary file path.
            hash_value (str): The SHA-256 hash of the file.

        Returns:
            tuple: (file_instance, hash_instance).
        """
        try:
            size = os.path.getsize("/tmp/"+ tmp_path)
        except FileNotFoundError:
            logger.error("Temporary file not found at: %s", tmp_path)
            size = 0

        with transaction.atomic():
            # Get or create the Hash instance for the file
            hash_instance, created = Hash.objects.get_or_create(
                value=hash_value,
                defaults={"hashtype": "SHA-256"}
            )
            if not created:
                hash_instance.times_sent = F('times_sent') + 1
                hash_instance.save()

            # Look up an existing File instance linked to this hash
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
            # Determine the file type (extension) or mark as 'unknown'
            filetype = tmp_path.split('.')[-1] if '.' in tmp_path else 'unknown'
            file_instance = File.objects.create(
                linked_hash=hash_instance,
                file_path=file_path,
                tmp_path=tmp_path,
                filetype=filetype,
                size=size
            )
            # Create the linking relation between the hash and the file
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
            # Handle potential FileField by accessing the 'name' attribute if available
            existing_name = file_instance.file_path
            if hasattr(existing_name, 'name'):
                existing_name = existing_name.name

            # Update other_names if the new file name differs from the stored one
            if file_path and existing_name != file_path:
                other_names = file_instance.other_names
                if not other_names:
                    other_names = []
                elif isinstance(other_names, str):
                    # Convert a string representation of a list into an actual list
                    other_names = [name.strip() for name in other_names.strip('[]').split(',') if name.strip()]
                if file_path not in other_names:
                    other_names.append(file_path)
                file_instance.other_names = str(other_names)

            # Update temporary path, file size, and increment times_sent safely
            file_instance.tmp_path = tmp_path
            file_instance.size = size
            file_instance.times_sent = F('times_sent') + 1
            file_instance.save()
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
                # Read file in 8 KB chunks until EOF
                for chunk in iter(lambda: f.read(8192), b""):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except FileNotFoundError:
            logger.error("File not found: %s", file_path)
            return None
