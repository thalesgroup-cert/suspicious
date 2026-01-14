import logging

import json

import chromadb
from chromadb.config import Settings

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
    add_attachments_to_item,
    build_mail_observables_from_headers,
    build_mail_observables_from_html,
    build_mail_attachments_paths
)

from case_handler.models import Case

from minio import Minio
from minio.error import S3Error
from ..base import BaseAnalyzer

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

thehive_config = config.get('thehive', {})
minio_config = config.get("minio", {})
logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class AnalyzerAI(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if self.summary:
                # Convert "malscore" to float and use it as the score.
                response["score"] = int(round(float(self.summary.get("malscore", 5))))
                response["confidence"] = int(round(float(self.summary.get("confidence", 0)) * 10))

                # Set level based on the classification value in summary.
                response["level"] = self.summary.get("classification", "info").lower()

            # Ensure response includes a "details" dictionary.
            response.setdefault("details", {})
            if self.full:
                # Add classification probabilities if available.
                if "classification_probabilities" in self.full:
                    response["details"]["classification_probabilities"] = self.full["classification_probabilities"]
                # Merge full report details.
                if "report" in self.full:
                    response["details"]["report"] = self.full["report"]
                # Optionally, add additional full fields if needed.
                for key in ["malscore", "confidence", "classification"]:
                    if key in self.full:
                        response["details"][f"{key}"] = self.full[key]

                # Get chroma client
                try:
                    chroma_client = chromadb.PersistentClient(path="/app/Suspicious/chromadb", settings=Settings(anonymized_telemetry=False))
                    logger.info(f"Chroma client: {chroma_client}")
                except Exception as e:
                    chroma_client = None
                    logger.error(f"Error getting chroma client: {e}")

                # Get suspicious collection
                try:
                    if chroma_client:
                        suspicious_collection = get_suspicious_collection(chroma_client)
                        logger.info(f"Suspicious collection: {suspicious_collection}")
                except Exception as e:
                    logger.error(f"Error getting suspicious collection: {e}")

                alert_id = ''
                sourceRef = ''

                # Check if mail is dangerous
                try:
                    malscore_val = float(response["details"].get("malscore", response.get("score", 5)))
                except Exception:
                    malscore_val = 5.0
                if malscore_val > 6.5:
                    logger.info("Mail is considered dangerous")

                    try:
                        self.full["report"]["analyzed_mail_headers"] = parse_and_decode_defaultdict(str(self.full["report"]["analyzed_mail_headers"])) # Decode headers
                    except Exception as e_hdr:
                        logger.error(f"Error decoding analyzed_mail_headers: {e_hdr}")

                    # Check if sender domain is in campaign allow_list
                    sender_domain = extract_sender_domain_from_headers(self.full["report"]["analyzed_mail_headers"])
                    is_allow_listed = sender_domain is not None and is_domain_in_campaign_allow_list(sender_domain)

                    if is_allow_listed:
                        logger.info(f"Sender domain {sender_domain} is in campaign allow_list, skipping phishing campaign check.")
                        return response
                    else:
                        logger.info(f"Sender domain {sender_domain} is not in campaign allow_list, proceeding with phishing campaign check.")
                        THE_HIVE_URL = thehive_config.get('url', '')
                        THE_HIVE_KEY = thehive_config.get('api_key', '')

                        logger.info("Checking if phishing is in phishing campaign...")

                        embedding = response["details"]["report"]["email_embedding"]

                        # Get similar mails
                        similar_dangerous_mails = get_similar_dangerous_mails(embedding, suspicious_collection)

                        # Check if phishing campaign
                        phishing_campaign = get_phishing_campaign(similar_dangerous_mails)
                        if phishing_campaign:
                            logger.info("Phishing campaign detected!")

                            # Check if alert or case exists
                            try:
                                alert_id = get_most_common_alert_id(phishing_campaign)
                            except Exception as e:
                                logger.error(f"Error getting most common alert ID: {e}")
                            if alert_id == '':
                                logger.info("Creating an alert...")
                                try:
                                    item = create_new_alert(
                                        None,
                                        PHISHING_CAMPAIGN_TEMPLATE["title"](get_most_common_subject(phishing_campaign)),
                                        PHISHING_CAMPAIGN_TEMPLATE["description"](self.full["classification"], self.full["sub_classification"], self.full["report"]["analyzed_mail_content"]),
                                        PHISHING_CAMPAIGN_TEMPLATE["severity"],
                                        PHISHING_CAMPAIGN_TEMPLATE["tlp"],
                                        PHISHING_CAMPAIGN_TEMPLATE["pap"],
                                        "Suspicious",
                                        THE_HIVE_URL,
                                        THE_HIVE_KEY,
                                        PHISHING_CAMPAIGN_TEMPLATE["tags"]
                                    )
                                    sourceRef = item["sourceRef"]
                                    alert_id = item["_id"]
                                    item_type = "alert"
                                    logger.info("Alert created!")
                                    logger.info(f"Updating suspicious collection {suspicious_collection}...")
                                    try:
                                        update_suspicious_collection(suspicious_collection, phishing_campaign, alert_id, sourceRef)
                                        logger.info("Suspicious collection updated!")
                                    except Exception as e:
                                        logger.error(f"Error updating suspicious collection: {e}")
                                except Exception as e:
                                    logger.error(f"Error creating alert: {e}")
                                    item = None
                                    item_type = ''
                            else:
                                logger.info(f"Getting alert {alert_id}...")
                                try:
                                    item_type, item = get_item_from_id(alert_id, THE_HIVE_URL, THE_HIVE_KEY)
                                    logger.info("Got alert!")
                                except Exception as e:
                                    logger.error(f"Error getting alert {alert_id}: {e}")
                                    item = None
                                    item_type = ''

                            if isinstance(item, dict) and item["status"] not in ["Duplicate", "False Positive", "Information", "Rejected"]: 
                                suspicious_case_ids = [int(metadata['suspicious_case_id']) for metadata in phishing_campaign['metadatas'][0]] + [self.suspicious_case_id]
                                for suspicious_case_id in suspicious_case_ids:
                                    logger.info(f"Adding observables/attachments for {item_type} {suspicious_case_id}...")
                                    try:
                                        case = Case.objects.get(id=suspicious_case_id)
                                        mail_id = str(case.fileOrMail.mail.mail_id)
                                        logger.info(f"Mail id for case {suspicious_case_id}: {mail_id}")

                                        eml = ''
                                        txt = ''
                                        headers = ''
                                        html = ''
                                        minio_client = Minio(
                                            minio_config.get("endpoint"),
                                            access_key=minio_config.get("access_key"),
                                            secret_key=minio_config.get("secret_key"),
                                            secure=False
                                        )
                                        for bucket in minio_client.list_buckets():
                                            if bucket.name.endswith(f"-{mail_id.split('-')[0]}"):
                                                try:
                                                    objects = minio_client.list_objects(bucket.name, prefix=mail_id, recursive=False)
                                                    for obj in objects:
                                                        logger.info(f"Checking object: {obj.object_name} in bucket: {bucket.name}")
                                                        if obj.object_name.startswith(mail_id):
                                                            expected_headers_key = f"{mail_id}/{mail_id}.headers"
                                                            data = minio_client.get_object(bucket.name, expected_headers_key)
                                                            headers = data.read().decode('utf-8')
                                                            logger.info(f"Found .headers file in bucket: {bucket.name}")
                                                        if obj.object_name.startswith(mail_id):
                                                            expected_eml_key = f"{mail_id}/{mail_id}.eml"
                                                            data = minio_client.get_object(bucket.name, expected_eml_key)
                                                            eml = data.read().decode('utf-8')
                                                            logger.info(f"Found .eml file in bucket: {bucket.name}")
                                                        if obj.object_name.startswith(mail_id):
                                                            expected_txt_key = f"{mail_id}/{mail_id}.txt"
                                                            data = minio_client.get_object(bucket.name, expected_txt_key)
                                                            txt = data.read().decode('utf-8')
                                                            logger.info(f"Found .txt file in bucket: {bucket.name}")
                                                        if obj.object_name.startswith(mail_id):
                                                            expected_html_key = f"{mail_id}/{mail_id}.html"
                                                            data = minio_client.get_object(bucket.name, expected_html_key)
                                                            html = data.read().decode('utf-8')
                                                            logger.info(f"Found .html file in bucket: {bucket.name}")
                                                except S3Error as e:
                                                    logger.error(f"Error listing objects in bucket {bucket.name}: {e}")
                                        try:
                                            add_attachments_to_item(item_type, alert_id, build_mail_attachments_paths(headers, eml, txt, html, suspicious_case_id), THE_HIVE_URL, THE_HIVE_KEY)
                                        except Exception as e:
                                            logger.error(f"Error adding attachments for {item_type} {suspicious_case_id}: {e}")
                                        try:
                                            add_observables_to_item(item_type, alert_id, build_mail_observables_from_headers(headers), THE_HIVE_URL, THE_HIVE_KEY)
                                        except Exception as e:
                                            logger.error(f"Error adding headers observables for {item_type} {suspicious_case_id}: {e}")
                                        try:
                                            add_observables_to_item(item_type, alert_id, build_mail_observables_from_html(html), THE_HIVE_URL, THE_HIVE_KEY)
                                        except Exception as e:
                                            logger.error(f"Error adding HTML observables for {item_type} {suspicious_case_id}: {e}")
                                    except Exception as e:
                                        logger.error(f"Error adding observables/attachments for {item_type} {suspicious_case_id}: {e}")
                        else:
                            logger.info("No phishing campaign detected.")
                else:
                    logger.info("Mail is not considered dangerous")
                logger.info("Adding mail to suspicious collection...")
                timestamp = add_to_suspicious_collection(self.full, alert_id, sourceRef, self.suspicious_case_id, suspicious_collection)
                logger.info(f"Mail added to suspicious collection with timestamp: {timestamp}")
        except Exception as e:
            logger.error(f"[cortex_analyzers.py] AnalyzerAI: error processing report: {e}")
        return response