"""HashiCorp Vault secret client with a settings.json dev fallback.

Read order:
  - VAULT_ADDR set   -> Vault KV v2 at suspicious/data/<key>, field "value".
  - VAULT_ADDR unset -> settings.json dotted lookup (local dev / CI).

In-process cache; values are small and rotation is out of scope here.
``fail_fast=True`` (used at boot for SECRET_KEY + DB password) turns any
Vault error into SystemExit(1) with a readable message — no silent
fallback to plaintext when Vault is configured.
"""
from __future__ import annotations

import os
import sys
from typing import Any

from suspicious._config_common import settings_get

_VAULT_MOUNT = "suspicious"

_CACHE: dict[str, Any] = {}
# Boxed singleton so tests can reset it without module reload.
_client_singleton: list = [None]


def _make_client():
    import hvac

    client = hvac.Client(url=os.environ["VAULT_ADDR"])
    client.auth.approle.login(
        role_id=os.environ["VAULT_ROLE_ID"],
        secret_id=os.environ["VAULT_SECRET_ID"],
    )
    if not client.is_authenticated():
        raise RuntimeError("Vault AppRole authentication failed")
    return client


def _client():
    if _client_singleton[0] is None:
        _client_singleton[0] = _make_client()
    return _client_singleton[0]


def _read_from_vault(key: str) -> Any:
    resp = _client().secrets.kv.v2.read_secret_version(
        path=key, mount_point=_VAULT_MOUNT, raise_on_deleted_version=True,
    )
    return resp["data"]["data"]["value"]


def get_secret(key: str, default: Any = None, *, fail_fast: bool = False) -> Any:
    """Resolve a secret by its dotted settings key.

    ``fail_fast`` exits the process on any Vault error (boot-critical keys).
    """
    if key in _CACHE:
        return _CACHE[key]

    if not os.environ.get("VAULT_ADDR"):
        # Dev / CI fallback — read the same key out of settings.json.
        value = settings_get(key, default)
        _CACHE[key] = value
        return value

    try:
        value = _read_from_vault(key)
    except Exception as exc:  # noqa: BLE001 — boot must fail readably
        message = (
            f"FATAL: could not read secret '{key}' from Vault at "
            f"{os.environ.get('VAULT_ADDR')}: {exc}"
        )
        if fail_fast:
            sys.stderr.write(f"\n{message}\n\n")
            raise SystemExit(1) from exc
        raise RuntimeError(message) from exc

    _CACHE[key] = value
    return value
