import logging
from urllib.parse import urlparse
import json
from typing import Optional, Tuple

from domain_process.domain_utils.domain_handler import DomainHandler
from url_process.models import URL
from domain_process.models import Domain, DomainInIocs

logger = logging.getLogger(__name__)

try:
    with open("/app/settings.json") as config_file:
        config = json.load(config_file)
except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.error(f"Config loading error: {e}")
    config = {}

suspicious_config = config.get('suspicious', {})


class URLHandler:
    """
    Handler class to process URLs and related Domain objects.
    """

    def handle_url(self, url: str) -> Tuple[Optional[URL], Optional[Domain]]:
        """
        Process the given URL or domain string to create or update corresponding models.

        Args:
            url (str): The URL string to handle.

        Returns:
            Tuple[Optional[URL], Optional[Domain]]:
                - URL instance and Domain instance if the URL is valid.
                - (None, Domain instance) if input is a domain.
                - (None, None) if input is invalid or processing fails.
        """
        domain_handler = DomainHandler()
        domain_type = domain_handler.validate_domain(url)

        if domain_type == "Domain":
            domain_instance = domain_handler.handle_domain(url)
            return None, domain_instance
        elif domain_type == "Url":
            return URLHandler()._create_or_update_url(url)
        else:
            return None, None

    def _create_or_update_url(self, url: str) -> Tuple[Optional[URL], Optional[Domain]]:
        """
        Create or update URL and corresponding DomainInIocs models.

        Args:
            url (str): The URL string to create or update.

        Returns:
            Tuple[Optional[URL], Optional[Domain]]:
                The URL and Domain instances if successful, otherwise (None, None).
        """
        try:
            url_instance, created = URL.objects.get_or_create(address=url)
            if not created:
                self._increment_times_sent(url_instance)

            domain_str = self.get_domain(url_instance.address)
            if domain_str is None:
                logger.error(f"Failed to extract domain from URL: {url}")
                return None, None

            domain_instance = self._create_or_update_domain(domain_str)
            if domain_instance is None:
                return None, None

            domain_in_iocs, created = DomainInIocs.objects.get_or_create(domain=domain_instance)
            domain_in_iocs.url = url_instance
            domain_in_iocs.save()

            return url_instance, domain_instance

        except Exception as e:
            logger.error(f"Error handling URL {url}: {e}")
            return None, None

    def _create_or_update_domain(self, domain: str) -> Optional[Domain]:
        """
        Create or update a Domain model instance.

        Args:
            domain (str): The domain string to create or update.

        Returns:
            Optional[Domain]: The Domain instance if successful, None otherwise.
        """
        try:
            domain_instance, created = Domain.objects.get_or_create(value=domain)
            if not created:
                self._increment_times_sent(domain_instance)
            return domain_instance
        except Exception as e:
            logger.error(f"Error handling domain {domain}: {e}")
            return None

    def _increment_times_sent(self, instance) -> None:
        """
        Increment the times_sent attribute of a given model instance and save it.

        Args:
            instance: The model instance with a times_sent field.
        """
        instance.times_sent = (instance.times_sent or 0) + 1
        instance.save(update_fields=["times_sent"])

    @staticmethod
    def get_domain(url: str) -> Optional[str]:
        """
        Extract the domain from a given URL string, validating its type.

        Args:
            url (str): The URL string from which to extract the domain.

        Returns:
            Optional[str]: The domain string if valid, otherwise None.
        """
        try:
            domain = urlparse(url).netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]

            domain_type = DomainHandler().validate_domain(domain)
            if domain_type in {"Domain", "Url"}:
                return domain
            return None
        except Exception as e:
            logger.error(f"Error extracting domain from URL {url}: {e}")
            return None
