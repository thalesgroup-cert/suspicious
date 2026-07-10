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
import time
from typing import Any

from suspicious._config_common import settings_get

_VAULT_MOUNT = "suspicious"

_CACHE_TTL = 60
_CACHE: dict[str, Any] = {}
_client_singleton: list = [None]


class SecretStoreUnavailable(RuntimeError):
    """Raised when a secret write is attempted with no Vault configured."""


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
    Cache entries carry a short TTL so a UI-driven Vault write propagates to
    other worker processes within ``_CACHE_TTL`` seconds.
    """
    cached = _CACHE.get(key)
    if cached is not None and cached[1] > time.monotonic():
        return cached[0]

    if not os.environ.get("VAULT_ADDR"):
        value = settings_get(key, default)
        _cache_set(key, value)
        return value

    try:
        value = _read_from_vault(key)
    except Exception as exc:  # noqa: BLE001 — boot must fail readably
        import hvac

        if isinstance(exc, hvac.exceptions.InvalidPath):
            _cache_set(key, default)
            return default
        message = (
            f"FATAL: could not read secret '{key}' from Vault at "
            f"{os.environ.get('VAULT_ADDR')}: {exc}"
        )
        if fail_fast:
            sys.stderr.write(f"\n{message}\n\n")
            raise SystemExit(1) from exc
        raise RuntimeError(message) from exc

    _cache_set(key, value)
    return value


def _cache_set(key: str, value: Any) -> None:
    _CACHE[key] = (value, time.monotonic() + _CACHE_TTL)


def set_secret(key: str, value: str) -> None:
    """Write a secret to Vault KV v2 and refresh this process's cache.

    Raises ``SecretStoreUnavailable`` when no Vault is configured —
    settings.json is read-only config, never a write target.
    """
    if not os.environ.get("VAULT_ADDR"):
        raise SecretStoreUnavailable(
            "no Vault configured (VAULT_ADDR unset); cannot store secret"
        )
    _client().secrets.kv.v2.create_or_update_secret(
        path=key, secret={"value": value}, mount_point=_VAULT_MOUNT,
    )
    _cache_set(key, value)
