import logging
import json
from pathlib import Path

import validators
import tldextract
from django.utils import timezone
from domain_process.models import Domain

logger = logging.getLogger(__name__)

CONFIG_PATH = Path("/app/settings.json")
TLD_CACHE_DIR = Path("/app/Suspicious/domain_process/domain_utils/public")

def load_config(path: Path) -> dict:
    """
    Load the configuration JSON file from the specified path.

    Args:
        path (Path): Path to the JSON configuration file.

    Returns:
        dict: Parsed configuration dictionary, or empty dict if error.
    """
    try:
        with path.open() as f:
            return json.load(f)
    except Exception as e:
        logger.error("Failed to load config: %s", e)
        return {}

config = load_config(CONFIG_PATH)
suspicious_config = config.get('suspicious', {})
extractor = tldextract.TLDExtract(
    cache_dir=str(TLD_CACHE_DIR),
    fallback_to_snapshot=True
)

def normalize_domain(domain: str) -> str | None:
    """
    Normalize a domain by extracting its registered form (eTLD+1).

    Example:
        'www.example.co.uk' -> 'example.co.uk'

    Args:
        domain (str): The input domain.

    Returns:
        str | None: Normalized registered domain, or None on error.
    """
    try:
        extracted = extractor(domain)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return None
    except Exception as e:
        logger.exception("Failed to normalize domain '%s': %s", domain, e)
        return None

class DomainHandler:
    """
    Handles domain parsing, validation, normalization and persistence using Django models.
    """

    @staticmethod
    def validate_email(email: str) -> str | None:
        """
        Validate an email address using the `validators` library.

        Args:
            email (str): The email address to validate.

        Returns:
            str | None: "Mail" if valid, otherwise None.
        """
        return "Mail" if validators.email(email) else None

    def validate_domain(self, domain: str) -> str | None:
        """
        Validate a domain string. Supports full URLs and plain domains.

        Args:
            domain (str): The domain or URL to validate.

        Returns:
            str | None:
                - "Url" for valid URLs.
                - "Domain" for valid plain domains.
                - "Invalid Domain" if invalid.
                - None on unexpected error.
        """
        if not domain:
            return "Invalid Domain"

        try:
            if validators.url(domain):
                return "Url"

            extracted = extractor(domain)
            if extracted.domain and extracted.suffix:
                return "Domain"
            return "Invalid Domain"
        except Exception as e:
            logger.exception("Domain validation error for input '%s': %s", domain, e)
            return None

    

    def handle_domain(self, domain: str) -> Domain | None:
        """
        Normalize and register a domain in the database. Updates timestamp if already present.

        Args:
            domain (str): The input domain string (can be full URL or raw domain).

        Returns:
            Domain | None: The Domain model instance, or None if invalid or on failure.
        """
        if not domain:
            logger.warning("Empty domain input.")
            return None

        try:
            normalized = normalize_domain(domain)
        except Exception as e:
            logger.exception("Exception normalizing domain '%s': %s", domain, e)
            return None

        if not normalized:
            logger.warning("Could not normalize domain: %s", domain)
            return None

        try:
            domain_instance, created = Domain.objects.get_or_create(value=normalized)
            if not created:
                domain_instance.last_update = timezone.now()
                domain_instance.save()
            return domain_instance
        except Exception as e:
            logger.exception("Error handling domain '%s' (normalized as '%s'): %s", domain, normalized, e)
            return None
