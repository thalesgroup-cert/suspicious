import os
import json
import logging
import pathlib
import time

import requests

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


def _api_to_feeder_json(api: dict, local: dict) -> dict:
    """Translate the backend config-API response (settings.json shape) plus the
    local file (connectors, working path, polling) into the feeder's config.json
    shape that MainConfig.from_json expects.

    Note: MainConfig.from_json reads the S3 bucket config under the top-level
    ``s3`` key (not ``minio``) and the SMTP config under ``mail``.
    """
    email = api.get("email", {})
    s3 = api.get("storage", {}).get("s3", {})
    smtp = email.get("smtp", {})
    content = email.get("content", {})
    links = email.get("links", {})
    merged = dict(local)
    merged["s3"] = {
        "endpoint": s3.get("endpoint", ""),
        "access_key": s3.get("access_key", ""),
        "secret_key": s3.get("secret_key", ""),
        "secure": bool(s3.get("secure", False)),
    }
    merged["mail"] = {
        # SMTP credentials
        "server": smtp.get("server", ""),
        "port": smtp.get("port", 25),
        "username": smtp.get("username", ""),
        "password": smtp.get("password", ""),
        "tls": bool(smtp.get("tls", True)),
        # Branding / email content
        "footer": content.get("footer", ""),
        "group": content.get("team_name", ""),
        "company_name": content.get("global_domain", ""),
        "company_url": content.get("website", ""),
        "suspicious_web": links.get("submissions", ""),
        "glossary": links.get("glossary", ""),
        "inquiry": links.get("inquiry", ""),
        "inquiry_text": links.get("inquiry_text", ""),
        "security": links.get("security_contact", ""),
        "security_msg": links.get("security_text", ""),
        "socials": email.get("socials", {}),
        "logos": email.get("logos", {}),
    }
    return merged


def load_config_from_api(
    backend_url: str,
    token: str,
    local_config_path: pathlib.Path,
    cache_path: pathlib.Path,
    *,
    retries: int = 5,
    backoff: float = 2.0,
) -> "classes.models.configs.main_config.MainConfig":
    """Fetch shared config from the backend authority, merge with the local
    file, build a MainConfig. On backend failure, fall back to the last-good
    cache; if there is no cache, raise."""
    local = json.loads(local_config_path.read_text())
    url = backend_url.rstrip("/") + "/api/config/feeder/"
    headers = {"Authorization": f"Token {token}"}
    last_exc = None
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()
            api = resp.json()
            merged = _api_to_feeder_json(api, local)
            fd = os.open(cache_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as _f:
                _f.write(json.dumps(merged))
            return classes.models.configs.main_config.MainConfig.from_json(merged)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(backoff)
    if cache_path.exists():
        logging.getLogger("email-feeder").warning(
            "backend config unreachable (%s); using last-good cache", last_exc
        )
        merged = json.loads(cache_path.read_text())
        return classes.models.configs.main_config.MainConfig.from_json(merged)
    raise RuntimeError(f"cannot load config from backend and no cache: {last_exc}")
