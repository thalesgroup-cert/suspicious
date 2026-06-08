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

# Canonical env var. The legacy names SUSPICIOUS_SETTINGS_PATH / CONFIG_PATH
# are collapsed into this one (see the per-site swaps).
CONFIG_PATH = os.environ.get("SUSPICIOUS_CONFIG_PATH", "/app/settings.json")

_MISSING = object()


@lru_cache(maxsize=1)
def load_settings() -> dict:
    """Load and cache settings.json. Re-read env each call for testability."""
    path = os.environ.get("SUSPICIOUS_CONFIG_PATH", CONFIG_PATH)
    with open(path) as fh:
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
