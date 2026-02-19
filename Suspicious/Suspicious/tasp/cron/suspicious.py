import logging
from datetime import datetime, timedelta
import chromadb
from chromadb.config import Settings
from .utils import load_config
from .models import CronConfig
from case_handler.models import Case

logger = logging.getLogger("cron.suspicious")
cleanup_logger = logging.getLogger("tasp.cron.cleanup_phishing")
CONFIG_PATH = "/app/settings.json"

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
    path = cfg.suspicious_path or "/app/Suspicious/chromadb"
    cutoff = datetime.now() - timedelta(days=threshold_days)
    try:
        client = chromadb.PersistentClient(path=path, settings=Settings(anonymized_telemetry=False))
        collection = client.get_collection(name="suspicious_mails")
        items = collection.get()

        expired_ids = [
            items["ids"][i]
            for i, meta in enumerate(items.get("metadatas", []))
            if meta and "detection_date" in meta and datetime.strptime(meta["detection_date"], "%Y-%m-%d %H:%M:%S.%f") < cutoff
        ]

        if expired_ids:
            collection.delete(ids=expired_ids)
    except Exception:
        cleanup_logger.exception("Cleanup failed")
