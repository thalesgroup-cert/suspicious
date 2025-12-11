import os
import re
import logging
from domain_process.models import Domain, DomainInIocs
from domain_process.domain_utils.domain_handler import DomainHandler
from email_validator import validate_email, EmailNotValidError
from email_process.models import MailAddress
import json
from pathlib import Path

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

company_config = config.get('company_domains', None)
fetch_mail_logger = logging.getLogger('tasp.cron.fetch_and_process_emails')

class MailAddressHandler:

    def handle_mail(self, mail):
        """
        Handles mail form and creates a new MailAddress instance.
        If a mail with the same address already exists, it updates the existing instance instead.

        Args:
            mail (str): The email address to handle.

        Returns:
            MailAddress: The created or updated MailAddress instance, or None if there was an error.
        """
        try:
            mail_instance, created = MailAddress.objects.get_or_create(address=mail)
            if mail_instance:
                domain = get_domain(mail_instance)
                domain_instance = _create_or_update_domain(domain)
                domain_in_iocs, _ = DomainInIocs.objects.get_or_create(domain=domain_instance)
                domain_in_iocs.mail_address = mail_instance
                domain_in_iocs.save()
                is_valid, valid_email = is_valid_email(mail)

                if created and is_valid:
                    if is_valid_company_email(valid_email):
                        mail_instance.is_internal = True
                        mail_instance.save()

            return mail_instance
        except Exception as e:
            fetch_mail_logger.error(f"Error handling mail address: {str(e)}")
            return None


def _create_or_update_domain(domain):
    """
    Creates or updates a Domain instance.

    Args:
        domain (str): The domain value to create or update.

    Returns:
        Domain: The created or updated Domain instance.
    """
    try:
        domain_instance, created = Domain.objects.get_or_create(value=domain)
        if not created:
            domain_instance.times_sent += 1
            domain_instance.save()
        else:
            domain_instance = DomainHandler().handle_domain(domain)
            domain_instance.save()
        return domain_instance
    except Exception as e:
        fetch_mail_logger.error(f"Error creating or updating domain: {str(e)}")
        return None


def get_domain(mail):
    """
    Returns the domain of a mail.

    Args:
        mail (str): The email address.

    Returns:
        str or None: The domain of the email address if it is a domain or URL, None otherwise.
    """
    try:

        # First check if it's a valid email
        email_type = DomainHandler().validate_email(mail.address)
        if email_type == "Mail":
            domain = mail.address.split("@")[1]
            if domain:
                return domain
            else:
                fetch_mail_logger.warning(f"Error: Extracted domain is empty from mail: {mail}")
                return None

        # If not a valid email, check if it's a domain or URL
        domain_type = DomainHandler().validate_domain(mail)
        if domain_type == "Domain":
            return mail.address
        elif domain_type == "Url":
            # Extract the domain from the URL
            if "@" in mail:
                domain = mail.address.split("@")[1].split("/")[0]
                if domain:
                    return domain
                else:
                    fetch_mail_logger.warning(f"Error: Extracted domain is empty from URL: {mail}")
                    return None
            else:
                fetch_mail_logger.warning(f"Error: Invalid URL format (missing '@'): {mail}")
                return None
        else:
            fetch_mail_logger.warning(f"Error: Invalid domain type returned: {domain_type}")
            return None
    except Exception as e:
        fetch_mail_logger.error(f"Error handling mail address: {str(e)}")
        return None

def is_valid_email(email):
    try:
        # Valide l'adresse email et retourne sa forme normalisée
        valid = validate_email(email, check_deliverability=False)
        return True, valid.email.lower()
    except EmailNotValidError as e:
        return False, str(e)

def is_valid_company_email(email):
    try:
        # Validate email syntax and deliverability
        v = validate_email(email)
        normalized_email = v.email
        domain = normalized_email.split('@')[1].lower()
        for company_domain in company_config:
            company_domain = company_domain.lower()
            if domain == company_domain:
                return True
            else:
                return False
    except EmailNotValidError:
        return False