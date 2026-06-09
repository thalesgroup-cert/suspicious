# misp/config_loader.py
"""
Lazy MISP settings loader — raises at call time, not at import time.
"""
from __future__ import annotations
import logging
from .models import MISPConfig, MISPSettings

logger = logging.getLogger(__name__)


def load_misp_settings() -> MISPSettings:
    from settings.config import get_section

    primary   = get_section("integrations.misp.instances.primary")
    secondary = get_section("integrations.misp.instances.secondary")
    misp_cfg  = get_section("integrations.misp")

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
