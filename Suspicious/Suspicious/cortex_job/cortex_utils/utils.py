import json
import logging
import os
from models import CortexJobConfig

# Logger setup
fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

def load_config(config_path: str = "/app/settings.json") -> CortexJobConfig:
    """
    Load the configuration file and return it as a CortexJobConfig object.

    Args:
        config_path (str): Path to the configuration file.

    Returns:
        CortexJobConfig: The loaded configuration.
    """
    try:
        with open(config_path, "r") as config_file:
            config = json.load(config_file)
        return CortexJobConfig(**config.get("cortex", {}))
    except FileNotFoundError:
        fetch_mail_logger.error(f"Configuration file not found at {config_path}")
    except json.JSONDecodeError as e:
        fetch_mail_logger.error(f"Error parsing JSON config: {e}")
    return CortexJobConfig(url="", api_key="", proxies={})
