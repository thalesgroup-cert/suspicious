import logging
import json
from datetime import datetime, timedelta

import chromadb
from .utils import load_config
from .models import CronConfig
from case_handler.models import Case

logger = logging.getLogger("cron.suspicious")
cleanup_logger = logging.getLogger("tasp.cron.cleanup_phishing")
CONFIG_PATH = "/app/settings.json"

with open(CONFIG_PATH, "r") as f:
    settings = json.load(f)
chromadb_conf = settings.get("chromadb", {})
CHROMA_HOST = chromadb_conf.get("host", "chromadb")
CHROMA_PORT = chromadb_conf.get("port", 8000)
CHROMA_COLLECTION_NAME = chromadb_conf.get("collection_name", "suspicious")


def check_challengeable():
    """
    Check if cases are challengeable and update their status accordingly.
    """
    cases = Case.objects.filter(is_challengeable=True)
    for case in cases:
        if not case.was_published_recently():
            case.is_challengeable = False
            case.save(update_fields=["is_challengeable"])

def remove_old_suspicious_emails(config_path: str = CONFIG_PATH, threshold_days: int = 15) -> None:
    cfg: CronConfig = load_config(config_path)
    cutoff = datetime.now() - timedelta(days=threshold_days)

    try:
        client = chromadb.HttpClient(
            host=CHROMA_HOST,
            port=CHROMA_PORT,
        )
        collection = client.get_collection(name=CHROMA_COLLECTION_NAME)
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