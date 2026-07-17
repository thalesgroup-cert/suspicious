"""Django-free config helpers shared by the boot loader and the accessor.

Owns the single canonical settings-path env var and a dotted-path walk so
both ``suspicious.secrets`` (import-time, no Django) and ``settings.config``
(request-time) resolve config the same way.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any

CONFIG_PATH = os.environ.get("SUSPICIOUS_CONFIG_PATH", "/app/settings.json")

@lru_cache(maxsize=1)
def load_settings() -> dict[str, Any]:
    """Load and cache settings.json. Re-reads env each cache-miss for testability."""
    path = os.environ.get("SUSPICIOUS_CONFIG_PATH", "/app/settings.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def dotted_get(data: dict, key: str, default: Any = None) -> Any:
    """Walk ``key`` ('a.b.c') through nested dicts; return default if absent."""
    node: Any = data
    for part in key.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def settings_get(key: str, default: Any = None) -> Any:
    """Dotted lookup against settings.json."""
    return dotted_get(load_settings(), key, default)
