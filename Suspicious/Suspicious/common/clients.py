"""Harmonized client factories for tier-1 infrastructure services.

One construction path per backend service; config always comes from the
runtime-config accessors so Vault-overlaid secrets and DB overrides apply
uniformly. Factories raise on misconfiguration — call sites keep their own
try/except policy, as before."""
from __future__ import annotations

from minio import Minio

from settings.config import get_section


def get_s3_client() -> Minio:
    """MinIO/rustfs client from the shared ``storage.s3`` section."""
    cfg = get_section("storage.s3")
    return Minio(
        endpoint=cfg["endpoint"],
        access_key=cfg["access_key"],
        secret_key=cfg["secret_key"],
        secure=cfg.get("secure", False),
    )
