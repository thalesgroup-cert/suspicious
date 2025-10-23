import json
import logging
from pathlib import Path
from typing import Dict, Any
from profiles.profiles_utils.ldap import Ldap
from mail_feeder.utils.email_validation.validators import EmailValidatorService
from mail_feeder.utils.email_validation.models import ConfigModel

logger = logging.getLogger(__name__)


def load_config(config_path: str) -> Dict[str, Any]:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    with open(path) as config_file:
        return json.load(config_file)


def initialize_email_validator(company_domains):
    config = ConfigModel(company_domains=company_domains)
    return EmailValidatorService(config)


def create_ldap_user(user):
    try:
        Ldap.create_user(user)
        logger.info(f"LDAP user created: {user.username}")
    except Exception as e:
        logger.error(f"Failed to create LDAP user for {user.username}: {e}")
