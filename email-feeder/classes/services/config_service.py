# import os
# import requests
import json
import logging
import pathlib
import classes.models.configs.main_config


def load_config(
    config_path: pathlib.Path, logger: logging.Logger
) -> classes.models.configs.main_config.MainConfig:
    """
    Reads and parses a JSON configuration file.

    Args:
        config_path: The path to the JSON configuration file.
                    Defaults to 'config.json'.

    Returns:
        A MainConfig object containing all the project's configuration.

    Raises:
        FileNotFoundError: If the configuration file is not found.
        json.JSONDecodeError: If the configuration file is not valid JSON.
        Exception: For other potential I/O errors.
    """

    logger.info(f"Attempting to read configuration file from : {config_path}")

    if not config_path.exists():
        logger.error(f"Configuration file not found at: {config_path}")
        raise FileNotFoundError()

    try:
        with open(config_path, "r") as stream:
            raw_config = json.load(stream)
            config = classes.models.configs.main_config.MainConfig.from_json(
                json_object=raw_config
            )
            return config

    except (json.JSONDecodeError, Exception) as e:
        if isinstance(e, json.JSONDecodeError):
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
