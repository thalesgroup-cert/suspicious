# misp/config_loader.py
"""
Lazy MISP settings loader — raises at call time, not at import time.
"""
from __future__ import annotations
import json
import logging
from pathlib import Path
from .models import MISPConfig, MISPSettings

CONFIG_PATH = Path("/app/settings.json")
logger = logging.getLogger(__name__)


def load_misp_settings() -> MISPSettings:
    try:
        with open(CONFIG_PATH) as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Cannot load MISP settings from %s: %s" % (CONFIG_PATH, exc)) from exc

    misp_cfg = raw.get("integrations", {}).get("misp", {})
    instances = misp_cfg.get("instances", {})
    primary   = instances.get("primary",   {})
    secondary = instances.get("secondary", {})

    return MISPSettings(
        suspicious=MISPConfig(
            url=primary.get("url", "http://localhost:8880"),
            key=primary.get("api_key", ""),
            ssl_verify=bool(primary.get("ssl_verify", False)),
        ),
        security=MISPConfig(
            url=secondary.get("url", "https://secondary-misp.example.com"),
            key=secondary.get("api_key", ""),
            ssl_verify=bool(secondary.get("ssl_verify", False)),
        ),
        tags=misp_cfg.get("default_tags", {}),
    )