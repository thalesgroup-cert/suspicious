import logging
from datetime import datetime, timedelta

import chromadb
from .utils import load_config
from case_handler.models import Case

logger = logging.getLogger("cron.suspicious")
cleanup_logger = logging.getLogger("tasp.cron.cleanup_phishing")


def _chroma_conf() -> dict:
    from settings.config import get_section
    return get_section("integrations.chromadb")


def check_challengeable():
    """
    Check if cases are challengeable and update their status accordingly.
    """
    cases = Case.objects.filter(is_challengeable=True)
    for case in cases:
        if not case.was_published_recently():
            case.is_challengeable = False
            case.save(update_fields=["is_challengeable"])

def remove_old_suspicious_emails(config_path: str = None, threshold_days: int = 15) -> None:
    if config_path is None:
        import os
        config_path = os.environ.get("SUSPICIOUS_CONFIG_PATH", "/app/settings.json")
    load_config(config_path)
    cutoff = datetime.now() - timedelta(days=threshold_days)

    cc = _chroma_conf()
    try:
        client = chromadb.HttpClient(
            host=cc.get("host", "chromadb"),
            port=cc.get("port", 8000),
        )
        collection = client.get_collection(name=cc.get("collection_name", "suspicious"))
        items = collection.get()

        expired_ids = [
            items["ids"][i]
            for i, meta in enumerate(items.get("metadatas", []))
            if meta
            and "detection_date" in meta
            and datetime.strptime(meta["detection_date"], "%Y-%m-%d %H:%M:%S.%f") < cutoff
        ]

        if expired_ids:
            collection.delete(ids=expired_ids)

    except Exception:
        cleanup_logger.exception("Cleanup failed")