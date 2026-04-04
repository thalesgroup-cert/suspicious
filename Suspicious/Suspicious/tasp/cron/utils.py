import logging
from contextlib import contextmanager
from typing import Generator, Optional
import json
from pathlib import Path
from .models import CronConfig

logger = logging.getLogger("cron.utils")


@contextmanager
def safe_execution(context: str):
    """
    Contexte uniforme pour logger et remonter les erreurs.
    Usage:
        with safe_execution("do something"):
            ...
    """
    try:
        yield
    except Exception as exc:
        logger.exception("[%s] unexpected error: %s", context, exc)
        raise


def load_config(path: str) -> CronConfig:
    """
    Charge le settings.json et mappe uniquement les champs utiles
    vers CronConfig.
    """
    raw = json.loads(Path(path).read_text())

    try:
        minio_raw = raw.get("storage", {}).get("s3")

        cortex_raw = raw.get("integrations", {}).get("cortex")

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

        if cortex_raw:
            config_data["cortex"] = {
                "url": cortex_raw.get("url", "http://cortex:9001"),
                "api_key": cortex_raw.get("api_key", "http://cortex:9001"),
            }

        return CronConfig(**config_data)

    except KeyError as e:
        raise ValueError(f"Missing required config key: {e}")


def ensure_dir(path: str) -> None:
    from pathlib import Path
    Path(path).mkdir(parents=True, exist_ok=True)
