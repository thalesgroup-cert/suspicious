import os
import logging
import ipaddress

from django.db.models import F

from ip_process.models import IP
import json
from pathlib import Path

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

suspicious_config = config.get('suspicious', {})
logger = logging.getLogger(__name__)

class IPHandler:

    def validate_ip(self, ip: str) -> str | None:
        """
        Validates an IP address and determines its type.

        :param ip: The IP address to validate.
        :return: A string indicating the IP type (e.g., 'Public IPv4', 'Private IPv6')
                 or None if the IP is invalid.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            ip_type = "IPv4" if ip_obj.version == 4 else "IPv6"

            if ip_obj.is_private:
                return f"Private {ip_type}"
            elif ip_obj.is_global:
                return f"Public {ip_type}"
            elif ip_obj.is_reserved:
                return f"Reserved {ip_type}"
            elif ip_obj.is_unspecified:
                return f"Unspecified {ip_type}"
            elif ip_obj.is_loopback:
                return f"Loopback {ip_type}"
            elif ip_obj.is_link_local:
                return f"Link-local {ip_type}"
            elif ip_obj.is_multicast:
                return f"Multicast {ip_type}"
            # Fallback in case none of the above conditions match
            return f"Unknown {ip_type}"
        except ValueError:
            return None  # The provided string is not a valid IP address

    def handle_ip(self, ip: str):
        """
        Processes the IP address by validating it and, if it is a public IP, updating or
        creating an IP instance in the database. Only public IP addresses are stored.

        :param ip: The IP address as a string.
        :return: The IP model instance if handled successfully, otherwise None.
        """
        try:
            ip = ip.strip()
            ip_type = IPHandler().validate_ip(ip)

            # Only process public IPs.
            if ip_type and ip_type.startswith("Public"):
                ip_instance, created = IP.objects.get_or_create(address=ip)
                if not created:
                    # Increment the counter in a race-condition-safe way
                    ip_instance.times_sent = F('times_sent') + 1
                ip_instance.save()
                return ip_instance
            else:
                logger.info("IP is not public: %s", ip_type)
                return None
        except Exception as e:
            logger.error("Error handling IP: %s", str(e))
            return None
