import logging
import json
import io
import zipfile
import requests
import chromadb
from chromadb.config import Settings
from minio import Minio
from minio.error import S3Error
from case_handler.models import Case
from ..base import BaseAnalyzer

from score_process.score_utils.thehive.utils import (
    parse_and_decode_defaultdict,
    get_phishing_campaign,
    get_most_common_subject,
    get_most_common_alert_id,
    extract_sender_domain_from_headers,
    is_domain_in_campaign_allow_list,
)
from score_process.score_utils.chromadb_utils import (
    get_suspicious_collection,
    get_similar_dangerous_mails,
    add_to_suspicious_collection,
    update_suspicious_collection,
)
from score_process.score_utils.thehive.phishing import (
    PHISHING_CAMPAIGN_TEMPLATE,
    create_new_alert,
    get_item_from_id,
    add_observables_to_item,
    build_mail_observables_from_headers,
    build_mail_observables_from_html,
)

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

thehive_config = config.get("thehive", {})
minio_config = config.get("minio", {})

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


# ------------------------------------------------------------------
# TheHive binary attachment helper
# ------------------------------------------------------------------

def add_binary_attachment_to_item(item_type, item_id, filename, file_bytes, hive_url, hive_key):
    if item_type not in ["alert", "case"]:
        raise ValueError("item_type must be 'alert' or 'case'")

    url = f"{hive_url}/api/v1/{item_type}/{item_id}/attachment"
    headers = {"Authorization": f"Bearer {hive_key}"}
    files = {"file": (filename, file_bytes, "application/zip")}

    response = requests.post(url, headers=headers, files=files, timeout=60)

    if response.status_code not in (200, 201):
        raise Exception(f"Attachment upload failed ({response.status_code}): {response.text}")

    return response.json()


# ------------------------------------------------------------------
# MinIO ZIP builder
# ------------------------------------------------------------------

def build_mail_zip_from_minio(minio_client, bucket_name, mail_id, reporter_name):
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
                logger.error(f"MinIO read error {obj.object_name}: {e}")

    zip_buffer.seek(0)
    safe_reporter = reporter_name.replace(" ", "_").replace("/", "_")
    filename = f"{safe_reporter}_{mail_id}.zip"

    return filename, zip_buffer.read()


# ------------------------------------------------------------------
# Analyzer
# ------------------------------------------------------------------

class AnalyzerAI(BaseAnalyzer):
    def process(self):
        response = super().process()

        try:
            # ----------------------
            # Base scoring
            # ----------------------
            if self.summary:
                response["score"] = int(round(float(self.summary.get("malscore", 5))))
                response["confidence"] = int(round(float(self.summary.get("confidence", 0)) * 10))
                response["level"] = self.summary.get("classification", "info").lower()

            response.setdefault("details", {})

            if not self.full:
                return response

            # Merge details
            for key in ["classification_probabilities", "report", "malscore", "confidence", "classification"]:
                if key in self.full:
                    response["details"][key] = self.full[key]

            # ----------------------
            # Chroma init
            # ----------------------
            try:
                chroma_client = chromadb.PersistentClient(
                    path="/app/Suspicious/chromadb",
                    settings=Settings(anonymized_telemetry=False)
                )
                suspicious_collection = get_suspicious_collection(chroma_client)
            except Exception as e:
                logger.error(f"Chroma init error: {e}")
                suspicious_collection = None

            # ----------------------
            # Danger threshold
            # ----------------------
            try:
                malscore_val = float(response["details"].get("malscore", response.get("score", 5)))
            except Exception:
                malscore_val = 5.0

            if malscore_val <= 6.5:
                logger.info("Mail not considered dangerous")
                return response

            logger.info("Mail considered dangerous")

            # Decode headers
            try:
                self.full["report"]["analyzed_mail_headers"] = parse_and_decode_defaultdict(
                    str(self.full["report"]["analyzed_mail_headers"])
                )
            except Exception as e:
                logger.error(f"Header decode error: {e}")

            # Allow list check
            sender_domain = extract_sender_domain_from_headers(self.full["report"]["analyzed_mail_headers"])
            if sender_domain and is_domain_in_campaign_allow_list(sender_domain):
                logger.info(f"Sender domain {sender_domain} allow‑listed")
                return response

            # ----------------------
            # Campaign detection
            # ----------------------
            THE_HIVE_URL = thehive_config.get("url", "")
            THE_HIVE_KEY = thehive_config.get("api_key", "")

            embedding = response["details"]["report"]["email_embedding"]
            similar_dangerous_mails = get_similar_dangerous_mails(embedding, suspicious_collection)
            phishing_campaign = get_phishing_campaign(similar_dangerous_mails)

            if not phishing_campaign:
                logger.info("No phishing campaign detected")
                return response

            logger.info("Phishing campaign detected")

            # ----------------------
            # Alert handling
            # ----------------------
            try:
                alert_id = get_most_common_alert_id(phishing_campaign)
            except Exception:
                alert_id = ""

            if alert_id:
                item_type, item = get_item_from_id(alert_id, THE_HIVE_URL, THE_HIVE_KEY)
            else:
                item = create_new_alert(
                    None,
                    PHISHING_CAMPAIGN_TEMPLATE["title"](get_most_common_subject(phishing_campaign)),
                    PHISHING_CAMPAIGN_TEMPLATE["description"](
                        self.full["classification"],
                        self.full["sub_classification"],
                        self.full["report"]["analyzed_mail_content"],
                    ),
                    PHISHING_CAMPAIGN_TEMPLATE["severity"],
                    PHISHING_CAMPAIGN_TEMPLATE["tlp"],
                    PHISHING_CAMPAIGN_TEMPLATE["pap"],
                    "Suspicious",
                    THE_HIVE_URL,
                    THE_HIVE_KEY,
                    PHISHING_CAMPAIGN_TEMPLATE["tags"],
                )
                alert_id = item["_id"]
                item_type = "alert"

                update_suspicious_collection(
                    suspicious_collection,
                    phishing_campaign,
                    alert_id,
                    item["sourceRef"],
                )

            # ----------------------
            # Attachments & observables
            # ----------------------
            suspicious_case_ids = (
                [int(m["suspicious_case_id"]) for m in phishing_campaign["metadatas"][0]]
                + [self.suspicious_case_id]
            )

            minio_client = Minio(
                minio_config.get("endpoint"),
                access_key=minio_config.get("access_key"),
                secret_key=minio_config.get("secret_key"),
                secure=False,
            )

            for suspicious_case_id in suspicious_case_ids:
                try:
                    case = Case.objects.get(id=suspicious_case_id)
                    mail_id = str(case.fileOrMail.mail.mail_id)
                    reporter_name = case.reporter

                    zip_name = None
                    zip_bytes = None
                    headers = ""
                    html = ""

                    for bucket in minio_client.list_buckets():
                        if bucket.name.endswith(f"-{mail_id.split('-')[0]}"):
                            zip_name, zip_bytes = build_mail_zip_from_minio(
                                minio_client,
                                bucket.name,
                                mail_id,
                                reporter_name,
                            )

                            try:
                                h = minio_client.get_object(bucket.name, f"{mail_id}/{mail_id}.headers")
                                headers = h.read().decode("utf-8")
                            except Exception:
                                pass

                            try:
                                h = minio_client.get_object(bucket.name, f"{mail_id}/{mail_id}.html")
                                html = h.read().decode("utf-8")
                            except Exception:
                                pass

                            break

                    if zip_bytes:
                        add_binary_attachment_to_item(
                            item_type,
                            alert_id,
                            zip_name,
                            zip_bytes,
                            THE_HIVE_URL,
                            THE_HIVE_KEY,
                        )

                    if headers:
                        add_observables_to_item(
                            item_type,
                            alert_id,
                            build_mail_observables_from_headers(headers),
                            THE_HIVE_URL,
                            THE_HIVE_KEY,
                        )

                    if html:
                        add_observables_to_item(
                            item_type,
                            alert_id,
                            build_mail_observables_from_html(html),
                            THE_HIVE_URL,
                            THE_HIVE_KEY,
                        )

                except Exception as e:
                    logger.error(f"Attachment/observable error for case {suspicious_case_id}: {e}")

            # ----------------------
            # Persist in Chroma
            # ----------------------
            add_to_suspicious_collection(
                self.full,
                alert_id,
                item.get("sourceRef", ""),
                self.suspicious_case_id,
                suspicious_collection,
            )

        except Exception as e:
            logger.error(f"AnalyzerAI processing error: {e}")

        return response
