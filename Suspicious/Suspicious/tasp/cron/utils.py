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
    Charge et valide la configuration JSON via Pydantic.
    """
    data = json.loads(Path(path).read_text())
    return CronConfig(**data)


def ensure_dir(path: str) -> None:
    from pathlib import Path
    Path(path).mkdir(parents=True, exist_ok=True)
