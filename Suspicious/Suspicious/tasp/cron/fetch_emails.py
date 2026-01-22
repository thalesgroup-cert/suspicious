import os
import shutil
import re
import logging
from typing import Optional
from minio import Minio
from minio.commonconfig import Tags
from pathlib import Path

from .utils import safe_execution, load_config, ensure_dir
from .models import CronConfig
from mail_feeder.minio_submission.minio import MinioEmailService

logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

CONFIG_PATH = "/app/settings.json"


def _init_minio_client(minio_conf) -> Optional[Minio]:
    try:
        return Minio(
            minio_conf.endpoint,
            access_key=minio_conf.access_key,
            secret_key=minio_conf.secret_key,
            secure=minio_conf.secure,
        )
    except Exception:
        logger.exception("MinIO client initialization failed")
        return None


def fetch_and_process_emails(config_path: str = CONFIG_PATH) -> None:
    """
    Entrée principale: crée un répertoire temporaire, parcourt les buckets MinIO marqués
    `Status=To Do`, télécharge les objets, archive et appelle le service de traitement.
    """
    cfg = load_config(config_path)
    base_temp = cfg.temp_dir
    ensure_dir(base_temp)
    logger.info("Starting email fetch job")
    try:
        _process_minio_buckets(cfg, base_temp)
    finally:
        try:
            shutil.rmtree(base_temp)
        except Exception:
            logger.exception("Failed to remove temp dir")
    logger.info("Email fetch job completed")


def _process_minio_buckets(cfg: CronConfig, base_path: str) -> None:
    client = _init_minio_client(cfg.minio)
    if not client:
        return

    minio_processor = MinioEmailService()

    for bucket in client.list_buckets():
        with safe_execution(f"process bucket {bucket.name}"):
            # skip non-To Do buckets
            try:
                if client.get_bucket_tags(bucket.name).get("Status") != "To Do":
                    continue
            except Exception:
                continue

            logger.debug("Processing bucket %s", bucket.name)
            objects = list(client.list_objects(bucket.name, recursive=True))
            bucket_path = os.path.join(base_path, bucket.name)
            ensure_dir(bucket_path)

            submission_path = None
            # download all objects into bucket_path
            for obj in objects:
                dst = os.path.join(bucket_path, obj.object_name)
                ensure_dir(os.path.dirname(dst))
                client.fget_object(bucket.name, obj.object_name, dst)
                if obj.object_name.endswith("submission.eml"):
                    submission_path = dst

            if not submission_path:
                logger.debug("No submission.eml found in %s", bucket.name)
                continue

            # each entry is a subdir like 202101010101-<hex>
            for entry in os.scandir(bucket_path):
                if entry.is_dir() and re.match(r"^\d{12}-[a-f0-9]+$", entry.name):
                    # copy submission.eml into the subdir as user_submission.eml
                    shutil.copy(submission_path, os.path.join(entry.path, "user_submission.eml"))
                    # create archive and process
                    shutil.make_archive(entry.path, "gztar", entry.path)
                    minio_processor.process_emails_from_minio_workdir(entry.path, bucket.name)

            # tag bucket as Done
            try:
                tags = Tags.new_bucket_tags()
                tags["Status"] = "Done"
                client.set_bucket_tags(bucket.name, tags)
            except Exception:
                logger.exception("Failed to tag bucket %s", bucket.name)
