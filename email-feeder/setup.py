import logging
import pathlib
import classes.config_service as config_service

# import os
import json
import sys
from typing import List, Dict, Any
import time

# import requests
from classes.mailbox import Mailbox

# --- Constants ---
DEFAULT_LOGGER_NAME = "email-feeder"
DEFAULT_LOG_FILE = "application.log"


# --- Logging Setup ---
def setup_logging(
    logger_name: str = DEFAULT_LOGGER_NAME,
    log_file: str = DEFAULT_LOG_FILE,
    file_log_level: int = logging.INFO,
    console_log_level: int = logging.ERROR,
    log_to_console: bool = True,
    log_to_file: bool = True,
) -> logging.Logger:
    """
    Configures and returns a logger instance.

    This function sets up a logger with a specified name, file handler,
    and console (stdout) handler. It allows customization of log levels
    for both handlers.

    Args:
        logger_name: The name for the logger.
        log_file: The path to the log file.
        file_log_level: The logging level for the file handler (e.g., logging.INFO, logging.DEBUG).
        console_log_level: The logging level for the console handler.
        log_to_console: Whether to enable console logging.
        log_to_file: Whether to enable file logging.

    Returns:
        A configured logging.Logger instance.
    """
    logger = logging.getLogger(logger_name)

    logger.setLevel(
        min(file_log_level, console_log_level)
        if log_to_file and log_to_console
        else (
            file_log_level
            if log_to_file
            else console_log_level
            if log_to_console
            else logging.WARNING
        )
    )

    if logger.hasHandlers():
        logger.handlers.clear()

    log_formatter = logging.Formatter(
        fmt="%(asctime)s UTC %(name)s %(levelname)s %(message)s",
        datefmt="%d/%m/%Y %H:%M:%S",
    )
    log_formatter.converter = time.gmtime

    if log_to_file:
        try:
            file_handler = logging.FileHandler(
                filename=log_file, mode="a", encoding="utf-8"
            )
            file_handler.setLevel(file_log_level)
            file_handler.setFormatter(log_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            print(
                f"Error setting up file logger at {log_file}: {e}. Logging to console instead.",
                file=sys.stderr,
            )
            if not log_to_console:
                log_to_console = True
                console_log_level = logging.INFO

    if log_to_console:
        stdout_handler = logging.StreamHandler(stream=sys.stdout)
        stdout_handler.setLevel(console_log_level)
        stdout_handler.setFormatter(log_formatter)
        logger.addHandler(stdout_handler)

    if not log_to_file and not log_to_console:
        logger.addHandler(logging.NullHandler())
        print(
            f"Warning: Logger '{logger_name}' has no handlers configured (file or console).",
            file=sys.stderr,
        )

    return logger


# --- Getter Function (optional, but can be good practice) ---
def get_logger(logger_name: str = DEFAULT_LOGGER_NAME) -> logging.Logger:
    """
    Retrieves a logger instance by name.
    It's generally recommended to call setup_logging once at the start
    of your application, and then use getLogger wherever you need it.
    """
    return logging.getLogger(logger_name)


# Return config file in dict type
def setup_config(
    config_path: pathlib.Path = pathlib.Path("config.json"),
) -> config_service.ConfigServiceGlobalConfig:
    """
    Reads and parses a JSON configuration file.

    Args:
        config_path: The path to the JSON configuration file.
                    Defaults to 'config.json'.

    Returns:
        A dictionary containing the configuration.

    Raises:
        FileNotFoundError: If the configuration file is not found.
        json.JSONDecodeError: If the configuration file is not valid JSON.
        Exception: For other potential I/O errors.
    """
    logger = get_logger()
    logger.info(f"Attempting to read configuration file from: {config_path}")
    try:
        return config_service.ConfigService(
            config_file_path=config_path
        ).read_config_file()
    except (FileNotFoundError, json.JSONDecodeError, Exception) as e:
        if isinstance(e, FileNotFoundError):
            logger.error(f"Configuration file not found at: {config_path}")
        elif isinstance(e, json.JSONDecodeError):
            logger.error(f"Error decoding JSON from {config_path}: {e}")
        else:
            logger.error(
                f"An unexpected error occurred while reading {config_path}: {e}"
            )
        raise e

    # logger.info("Reading config from Vault")

    # vault_addr = os.getenv("VAULT_ADDR", "http://localhost:8200")
    # vault_token = os.getenv("VAULT_TOKEN", "root")
    # vault_path = "kv/data/feeder"

    # try:
    #     response = requests.get(
    #         f"{vault_addr}/v1/{vault_path}",
    #         headers={"X-Vault-Token": vault_token},
    #         timeout=10,
    #         verify=False,
    #     )

    #     response.raise_for_status()
    #     secret_data = response.json()["data"]["data"]

    #     config = secret_data

    #     return config

    # except Exception as e:
    #     logger.error(f"Error loading config from Vault: {e}")
    #     raise


def setup_mailboxes(config: Dict[str, Any]) -> List[Mailbox]:
    """
    Connects to mailboxes defined in the configuration file and returns a list of Mailbox objects.

    Args:
        config: A dictionary containing the application configuration,
                expected to have a "mail-connectors" section and a "working-path".

    Returns:
        A list of successfully initialized and logged-in Mailbox objects.
    """
    mailboxes: List[Mailbox] = []
    logger = get_logger()
    if "mail-connectors" not in config:
        logger.error("Configuration missing 'mail-connectors' section.")
        return mailboxes

    if "working-path" not in config:
        logger.error("Configuration missing 'working-path'.")
        return mailboxes

    working_path = config["working-path"]

    for connector_type, instances in config["mail-connectors"].items():
        if not isinstance(instances, dict):
            logger.warning(
                f"Expected a dictionary of instances for connector '{connector_type}', got {type(instances)}. Skipping."
            )
            continue

        for instance_name, instance_config in instances.items():
            if not isinstance(instance_config, dict):
                logger.warning(
                    f"Instance '{instance_name}' for connector '{connector_type}' is not a valid dictionary. Skipping."
                )
                continue

            logger.info(
                f"Processing mailbox instance: {instance_name} (Type: {connector_type})"
            )

            if not instance_config.get("enable", False):
                logger.info(
                    f"Mailbox instance '{instance_name}' is disabled. Skipping."
                )
                continue

            try:
                host = instance_config["host"]
                port = instance_config["port"]
                login_user = instance_config["login"]
                password = instance_config["password"]
            except KeyError as e:
                logger.error(
                    f"Missing required configuration key {e} for instance '{instance_name}'. Skipping."
                )
                continue

            if not isinstance(port, int):
                try:
                    port = int(port)
                except ValueError:
                    logger.error(
                        f"Invalid port '{port}' for instance '{instance_name}'. Must be an integer. Skipping."
                    )
                    continue

            certfile = instance_config.get("certfile")
            keyfile = instance_config.get("keyfile")
            mailbox_to_monitor = instance_config.get("mailbox_to_monitor", "INBOX")

            try:
                mailbox = Mailbox(
                    server=host,
                    port=port,
                    username=login_user,
                    password=password,
                    tmp_dir=working_path,
                    certfile=certfile,
                    keyfile=keyfile,
                    mailbox_to_monitor=mailbox_to_monitor,
                )

                logger.info(
                    f"Attempting to login to mailbox: {instance_name} ({login_user}@{host})..."
                )
                mailbox.login()
                mailboxes.append(mailbox)
                logger.info(
                    f"Successfully connected and logged into mailbox: {instance_name}."
                )

            except ConnectionError as e:
                logger.error(
                    f"Failed to connect or login to mailbox '{instance_name}': {e}"
                )
            except KeyError as e:
                logger.error(
                    f"Configuration error for Mailbox '{instance_name}': Missing key {e}"
                )
            except Exception as e:
                logger.error(
                    f"An unexpected error occurred while setting up mailbox '{instance_name}': {e}",
                    exc_info=True,
                )

    if not mailboxes:
        logger.warning(
            "No mailboxes were successfully set up. Check configuration and logs."
        )
    else:
        logger.info(f"Successfully set up {len(mailboxes)} mailbox(es).")

    return mailboxes
