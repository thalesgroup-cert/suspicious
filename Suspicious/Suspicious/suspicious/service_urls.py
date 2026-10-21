"""Credentials for the internal data services (Valkey/Redis, Chroma token).

Env var first (compose passes ``.env`` to the containers), then the secret
store (Vault, or settings.json when Vault is off) so non-compose deployments
have a path. A missing secret is fatal at boot rather than a silent
unauthenticated connection."""
from __future__ import annotations

import os
from urllib.parse import quote

from django.core.exceptions import ImproperlyConfigured

from suspicious.secrets import get_secret


def redis_url(host: str, password: str, *, port: int = 6379, db: int = 0) -> str:
    auth = f":{quote(password, safe='')}@" if password else ""
    return f"redis://{auth}{host}:{port}/{db}"


def service_secret(env_name: str, settings_key: str, *, required: bool) -> str:
    value = os.environ.get(env_name) or get_secret(settings_key, "") or ""
    if required and not value:
        raise ImproperlyConfigured(
            f"{env_name} is not set (nor {settings_key} in the secret store). "
            "Internal services require authentication: run `make init` on a new "
            "install, or `make db-auth-migrate` on an existing deployment."
        )
    return value
