import logging
import os
import re
import shutil
import json
from datetime import date, datetime, timedelta
# from cortex4py.query import Lt
from django.utils import timezone
from case_handler.models import Case
from cortex4py.api import Api
from cortex4py.exceptions import CortexException
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
from cortex_job.models import Analyzer, AnalyzerReport
from dashboard.models import Kpi
from django.contrib.auth.models import User
from django.db import transaction
from mail_feeder.mail_utils.mail import EmailHandler, EmailProcessor
from minio import Minio
from minio.commonconfig import Tags
from profiles.profiles_utils.ldap import Ldap
import chromadb
from chromadb.config import Settings
# from concurrent.futures import ThreadPoolExecutor, as_completed

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

cortex_config = config.get("cortex", {})
TEMP_DIR = "/tmp/emailAnalysis/"

# Loggers
loggers = {
    'mail': logging.getLogger('tasp.cron.fetch_and_process_emails'),
    'cases': logging.getLogger('tasp.cron.update_ongoing_case_jobs'),
    'analyzers': logging.getLogger('tasp.cron.fetch_analyzer'),
    'cleanup': logging.getLogger('tasp.cron.cleanup_phishing'),
    'default': logging.getLogger(__name__)
}

def fetch_and_process_emails():
    """Fetch emails from MinIO buckets and process them."""
    loggers['mail'].info('Starting email fetch job')
    os.makedirs(TEMP_DIR, exist_ok=True)
    _process_minio_buckets(TEMP_DIR)
    shutil.rmtree(TEMP_DIR)
    loggers['mail'].info('Email fetch job completed')

def _init_minio_client():
    """Initialize and return a MinIO client using config."""
    try:
        return Minio(
            config["minio"]["endpoint"],
            access_key=config["minio"]["access_key"],
            secret_key=config["minio"]["secret_key"],
            secure=config["minio"].get("secure", False),
        )
    except Exception as e:
        loggers['mail'].critical(f"MinIO client initialization failed: {e}")
        return None

def _process_minio_buckets(base_path):
    """Iterate over MinIO buckets, process emails and tag them as done."""
    client = _init_minio_client()
    if not client:
        return

    email_handler = EmailHandler()
    processor = EmailProcessor(email_handler)

    for bucket in client.list_buckets():
        try:
            if client.get_bucket_tags(bucket.name).get("Status") != "To Do":
                continue
        except Exception:
            continue

        loggers['mail'].debug(f"Processing bucket: {bucket.name}")
        object_list = list(client.list_objects(bucket.name, recursive=True))
        bucket_path = os.path.join(base_path, bucket.name)
        os.makedirs(bucket_path, exist_ok=True)

        submission_path = None
        for obj in object_list:
            file_path = os.path.join(bucket_path, obj.object_name)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            client.fget_object(bucket.name, obj.object_name, file_path)
            if obj.object_name.endswith("submission.eml"):
                submission_path = file_path

        if not submission_path:
            continue

        for entry in os.scandir(bucket_path):
            if entry.is_dir() and re.match(r"^\d{12}-[a-f0-9]+$", entry.name):
                shutil.copy(submission_path, os.path.join(entry.path, "user_submission.eml"))
                shutil.make_archive(entry.path, 'gztar', entry.path)
                processor.process_emails_from_minio_workdir(entry.path)

        try:
            tags = Tags.new_bucket_tags()
            tags["Status"] = "Done"
            client.set_bucket_tags(bucket.name, tags)
        except Exception as e:
            loggers['mail'].error(f"Failed to tag bucket {bucket.name}: {e}")

def sync_cortex_analyzers():
    """Fetch enabled analyzers from Cortex and sync with local database."""
    url, key = cortex_config.get("url"), cortex_config.get("api_key")
    if not url or not key:
        loggers['analyzers'].error("Missing Cortex config (URL/API key)")
        return

    api = Api(url, key)
    try:
        remote_analyzers = api.analyzers.find_all({}, range='all')
    except CortexException as e:
        loggers['analyzers'].error(f"Cortex fetch failed: {e}")
        return

    if not remote_analyzers:
        return

    remote_names = []
    with transaction.atomic():
        for analyzer in remote_analyzers:
            _, created = Analyzer.objects.update_or_create(
                name=analyzer.name,
                defaults={
                    'analyzer_cortex_id': analyzer.id,
                    'is_active': True
                }
            )
            remote_names.append(analyzer.name)

        Analyzer.objects.exclude(name__in=remote_names).update(is_active=False)

def sync_user_profiles():
    """Sync user profiles with LDAP."""
    for user in User.objects.all():
        Ldap.create_user(user)

def update_ongoing_case_jobs():
    """Update Cortex jobs only for ongoing cases."""
    cases = Case.objects.filter(status="On Going")
    if not cases:
        loggers['cases'].info("No ongoing cases found.")
        return

    manager = CortexJobManager()
    for case in cases:
        try:
            manager.manage_jobs(case)
            case.save()
        except Exception as e:
            loggers['cases'].error(f"Case {case.id} update failed: {str(e)}")

def delete_old_analyzer_reports():
    cutoff_date = timezone.now() - timedelta(days=30)
    AnalyzerReport.objects.filter(creation_date__lt=cutoff_date).delete()

# def delete_old_cortex_jobs(batch_size: int = 100, max_workers: int = 8):
#     api = Api(cortex_config["url"], cortex_config["api_key"])
#     cutoff = (timezone.now() - timedelta(hours=48)).isoformat()
#     offset = 0

#     while True:
#         q = Lt('createdAt', cutoff)
#         rng = f"{offset}-{offset + batch_size - 1}"
#         jobs = list(api.jobs.find_all(q, range=rng, sort='-createdAt'))
#         if not jobs:
#             break

#         job_ids = [job.id for job in jobs]

#         with ThreadPoolExecutor(max_workers=max_workers) as executor:
#             futures = {executor.submit(api.jobs.delete, jid): jid for jid in job_ids}
#             for future in as_completed(futures):
#                 jid = futures[future]
#                 try:
#                     future.result()
#                 except Exception:
#                     pass

#         offset += batch_size

def sync_monthly_kpi():
    """Update or create the KPI object for the current month."""
    from dashboard.dash_utils.dashboard import update_all_kpi_stats

    today = date.today()
    month = today.strftime('%m')
    year = today.year

    kpi, created = Kpi.objects.get_or_create(month=month, year=year)
    update_all_kpi_stats(kpi, month, year)
    kpi.save()
    return kpi

def remove_old_suspicious_emails():
    """Delete suspicious emails from ChromaDB older than 15 days."""
    threshold_days = 15
    now = datetime.now()
    cutoff = now - timedelta(days=threshold_days)
    try:
        client = chromadb.PersistentClient(path="/app/Suspicious/chromadb", settings=Settings(anonymized_telemetry=False))
        collection = client.get_collection(name="suspicious_mails")
        items = collection.get()

        expired_ids = [
            items['ids'][i] for i, meta in enumerate(items['metadatas'])
            if meta and 'detection_date' in meta and datetime.strptime(meta['detection_date'], '%Y-%m-%d %H:%M:%S.%f') < cutoff
        ]

        if expired_ids:
            collection.delete(ids=expired_ids)
    except Exception as e:
        loggers['cleanup'].error(f"Cleanup failed: {e}")
