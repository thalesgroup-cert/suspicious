import logging
from minio import Minio
from minio.error import S3Error

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

def fetch_mail_files_from_minio(minio_client: Minio, mail_id: str, bucket_prefix: str):
    """Retrieve headers, eml, txt, html files from MinIO for a given mail."""
    headers = eml = txt = html = ""
    try:
        for bucket in minio_client.list_buckets():
            if bucket.name.endswith(bucket_prefix):
                objects = minio_client.list_objects(bucket.name, prefix=mail_id, recursive=True)
                for obj in objects:
                    obj_name = obj.object_name
                    if obj_name.endswith(".headers"):
                        headers = minio_client.get_object(bucket.name, obj_name).read().decode("utf-8")
                    elif obj_name.endswith(".eml"):
                        eml = minio_client.get_object(bucket.name, obj_name).read().decode("utf-8")
                    elif obj_name.endswith(".txt"):
                        txt = minio_client.get_object(bucket.name, obj_name).read().decode("utf-8")
                    elif obj_name.endswith(".html"):
                        html = minio_client.get_object(bucket.name, obj_name).read().decode("utf-8")
    except S3Error as e:
        logger.error(f"Error fetching files from MinIO: {e}")
    return headers, eml, txt, html


def is_mail_dangerous(malscore: float, threshold: float = 6.5) -> bool:
    return malscore > threshold


def is_sender_allowed(sender_domain: str, allow_list: list) -> bool:
    return sender_domain in allow_list
