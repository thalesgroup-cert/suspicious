import logging
from minio import Minio
from minio.error import S3Error
import io
import zipfile

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

def build_mail_zip_from_minio(minio_client, bucket_name, mail_id, reporter_name):
    """
    Returns (filename, bytes) for a ZIP containing all objects under mail_id/
    """
    zip_buffer = io.BytesIO()
    prefix = f"{mail_id}/"

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        objects = minio_client.list_objects(bucket_name, prefix=prefix, recursive=True)

        for obj in objects:
            try:
                data = minio_client.get_object(bucket_name, obj.object_name)
                content = data.read()
                arcname = obj.object_name.replace(prefix, "")
                zf.writestr(arcname, content)
            except Exception as e:
                logger.error(f"Error reading {obj.object_name} from {bucket_name}: {e}")

    zip_buffer.seek(0)

    safe_reporter = reporter_name.replace(" ", "_").replace("/", "_")
    filename = f"{safe_reporter}_{mail_id}.zip"

    return filename, zip_buffer.read()

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
