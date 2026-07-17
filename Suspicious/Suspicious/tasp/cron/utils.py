import logging
import json
import os
from pathlib import Path

from common.safe_exec import make_safe_execution
from .models import CronConfig

logger = logging.getLogger("tasp.cron.utils")

safe_execution = make_safe_execution("cron", logger)


def load_config(path: str) -> CronConfig:
    """
    Mappe uniquement les champs utiles vers CronConfig. Cortex and S3/minio
    config are read via the runtime accessor (non-secret fields from the DB,
    secrets from Vault), with a settings.json fallback; temp_dir and
    suspicious_path still come from the file.
    """
    raw = json.loads(Path(path).read_text())

    try:
        try:
            from settings.config import get_section
            minio_raw = get_section("storage.s3")
        except Exception:
            minio_raw = raw.get("storage", {}).get("s3") or {}

        config_data = {
            "s3": {
                "endpoint": minio_raw.get("endpoint"),
                "access_key": minio_raw.get("access_key"),
                "secret_key": minio_raw.get("secret_key"),
                "secure": minio_raw.get("secure", False),
            },
            "temp_dir": raw.get("app", {}).get("temp_dir", "/tmp/emailAnalysis/"),
            "suspicious_path": raw.get("integrations", {}).get("chromadb", {}).get(
                "suspicious_path", "/app/Suspicious/chromadb"
            ),
        }

        try:
            from settings.config import get_section
            cortex_raw = get_section("integrations.cortex")
        except Exception:
            cortex_raw = raw.get("integrations", {}).get("cortex") or {}

        if cortex_raw:
            config_data["cortex"] = {
                "url": cortex_raw.get("url", "http://cortex:9001"),
                "api_key": cortex_raw.get("api_key", ""),
            }

        return CronConfig(**config_data)

    except KeyError as e:
        raise ValueError(f"Missing required config key: {e}")


def ensure_dir(path: str) -> None:
    from pathlib import Path
    Path(path).mkdir(parents=True, exist_ok=True)


def _safe_object_name(raw_name: str) -> str:
    """
    Sanitize a MinIO object name before using it as a filesystem path component.
    Prevents path traversal via crafted object names (e.g. '../../etc/passwd').
    Raises ValueError if the sanitized name is empty or escapes the prefix.
    """
    normalized = os.path.normpath(raw_name.replace("\\", "/")).lstrip("/")
    if not normalized or normalized.startswith(".."):
        raise ValueError(f"Unsafe MinIO object name rejected: {raw_name!r}")
    return normalized
