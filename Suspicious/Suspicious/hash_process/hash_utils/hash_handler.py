import os
import re
import logging
from django.db.models import F
from django.db import transaction
from hash_process.models import Hash
from hashid import HashID
import json
from pathlib import Path

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

suspicious_config = config.get('suspicious', {})
logger = logging.getLogger(__name__)

class HashHandler:
    def __init__(self):
        self.hashid = HashID()  # Hash detection engine
        # Compile a regex for SSDEEP hashes (fuzzy hashing)
        self.ssdeep_regex = re.compile(r'^\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+$')
        # Define what an "empty" SSDEEP hash looks like
        self.empty_ssdeep = "0:"  

    def validate_hash(self, h: str) -> str | None:
        """
        Validates a hash and identifies its type.

        :param h: The hash value.
        :return: The hash type (e.g., 'MD5', 'SHA-256', 'SSDEEP') or None if invalid.
        """
        h = h.strip().lower()  # Normalize input
        hash_info = self.hashid.identifyHash(h)
        try:
            # Return the first detected hash type from the generator
            return next(hash_info).name
        except StopIteration:
            # No hash type was identified by hashid; try SSDEEP next
            pass

        if self.ssdeep_regex.match(h) and h != self.empty_ssdeep:
            return "SSDEEP"
        return None

    def handle_hash(self, hash_value: str):
        """
        Handles the hash form and returns the corresponding Hash instance.

        :param hash_value: The input string to be validated.
        :type hash_value: str
        :return: The Hash instance if created/updated successfully, otherwise None.
        """
        try:
            hash_value = hash_value.strip()  # Remove leading and trailing spaces
            hash_type = HashHandler().validate_hash(hash_value)

            if hash_type:
                hash_instance = HashHandler()._create_or_update_hash(hash_value=hash_value, hash_type=hash_type)
                if hash_instance:
                    return hash_instance
                else:
                    logger.error("Error creating/updating hash: %s", hash_value)
                    return None

            logger.error("Invalid hash: %s", hash_value)
            return None
        except Exception as e:
            logger.error("Error handling hash '%s': %s", hash_value, str(e))
            return None

    def _create_or_update_hash(self, hash_value: str, hash_type: str):
        """
        Creates a new Hash instance or updates an existing one.

        :param hash_value: The hash value.
        :param hash_type: The hash type.
        :return: The Hash instance if successful, otherwise None.
        """
        try:
            with transaction.atomic():
                hash_instance, created = Hash.objects.get_or_create(
                    value=hash_value, defaults={"hashtype": hash_type}
                )
                if not created:
                    # Safely increment the times_sent counter using an F expression
                    hash_instance.times_sent = F('times_sent') + 1
                    hash_instance.save()
                return hash_instance
        except Exception as e:
            logger.error("Error creating/updating hash '%s': %s", hash_value, str(e))
            return None
