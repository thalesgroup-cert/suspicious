import logging
import re
import base64

from datetime import datetime
from datetime import timedelta

import json
from django.db.models import Max
from urllib.parse import urlparse

import chromadb
from chromadb.config import Settings

from score_process.score_utils.utils import (
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
from score_process.score_utils.thehive import (
    PHISHING_CAMPAIGN_TEMPLATE,
    NEW_MAIL_IN_CAMPAIGN_TEMPLATE,
    create_new_alert,
    add_comment_to_item,
    get_item_from_id,
    add_observables_to_item,
    add_attachments_to_item,
    build_mail_observables_from_headers,
    build_mail_observables_from_html,
    build_mail_attachments_paths
)

from score_process.scoring.processing import (
    process_file_ioc,
    process_mail,
    process_ioc,
)
from score_process.scoring.case_score_calculation import calculate_final_scores

from score_process.scoring.case_update import (
    update_case_results,
    save_case_results,
    update_kpi_and_user_stats,
)
from score_process.scoring.misp import MISPHandler
from cortex_job.models import AnalyzerReport
from domain_process.domain_utils.domain_handler import DomainHandler
from file_process.models import File
from case_handler.models import Case
from mail_feeder.models import MailArchive, Mail

from minio import Minio
from minio.error import S3Error

from settings.models import (
    AllowListDomain,
    AllowListFile,
    AllowListFiletype,
)

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

thehive_config = config.get('thehive', {})
minio_config = config.get("minio", {})

logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')

soft_version = "1.0"
feeds_version = "1.0"

class CortexAnalyzer:
    @staticmethod
    def get_domain(url):
        """Extracts the domain from a URL or validates if it's a domain."""
        domain_type = DomainHandler().validate_domain(url)
        if domain_type == "Domain":
            return url
        elif domain_type == "Url":
            return urlparse(url).netloc
        return None

    @staticmethod
    def process_analyzer_reports(reports, analyzer_reports, artifact_value, case_id):
        """Processes and logs analyzer reports, handling success and failure cases."""
        failure_count = 0
        update_cases_logger.info(f"[cortex_analyzers.py] process_analyzer_reports: Processing {analyzer_reports}")
        for report in analyzer_reports:
            try:
                if report.status == "Success":
                    CortexAnalyzer.create_and_save_report(report, artifact_value, case_id)
                elif report.status == "Failure":
                    failure_count += CortexAnalyzer.handle_failure(report)

                update_cases_logger.info(
                    f"Processing report: ID={report.id}, Status={report.status}, Score={report.score}, Confidence={report.confidence}"
                )
                reports.append(report)
            except Exception as e:
                update_cases_logger.error(f"Error processing report: {e}")
        return failure_count

    @staticmethod
    def create_and_save_report(report, artifact_value, case_id):
        """Creates and updates a report object."""
        try:
            update_cases_logger.info(f"Creating report for artifact: {artifact_value}")
            result = CortexAnalyzer.create_report(
                report.report_summary, report.report_full, report.analyzer.name, artifact_value, report.type, case_id
            )
            result_json = json.loads(json.dumps(result))

            if result_json:
                report.score = result_json.get("score", 0)
                report.confidence = result_json.get("confidence", 0)
                report.category = result_json.get("category", "Unknown")
                report.level = result_json.get("level", "info")

            report.save()
        except Exception as e:
            update_cases_logger.error(f"Error saving report: {e}")

    @staticmethod
    def handle_failure(report):
        """Handles failed reports by setting default values."""
        report.score = 5
        report.confidence = 0
        report.category = "Failed task"
        report.level = "info"
        report.save()
        return 1

    @staticmethod
    def get_analyzer_reports_by_type_and_artifact(artifact_type, artifact):
        """Retrieves latest analyzer reports based on artifact type."""
        field_mapping = {
            "file": "file", "hash": "hash", "url": "url", "ip": "ip",
            "mail_body": "mail_body", "mail_header": "mail_header"
        }

        field_name = field_mapping.get(artifact_type)
        if not field_name:
            return None

        latest_reports = (
            AnalyzerReport.objects
            .filter(**{field_name: artifact})
            .values("analyzer_id")
            .annotate(latest_id=Max("id"))
        )

        return AnalyzerReport.objects.filter(id__in=[r["latest_id"] for r in latest_reports])

    @staticmethod
    def get_report(case):
        """
        Generates a report for the given case.

        Args:
            case: The case object for which the report is generated.

        Returns:
            None
        """
        from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
        if not case:
            update_cases_logger.warning("[score_check.py] get_report: Case does not exist.")
            return
        cortex_job_manager = CortexJobManager()
        reports = []
        total_scores = []
        total_confidences = []
        is_malicious = 0
        failure = 0
        mail = None

        try:
            # Process file or mail
            if case.fileOrMail:
                file = getattr(case.fileOrMail, 'file', None)
                if file:
                    update_cases_logger.info(f"[score_check.py] get_report: Processing file {file}")
                    failure += process_file_ioc(file, reports, total_scores, total_confidences, is_malicious, case.id)

                mail = getattr(case.fileOrMail, 'mail', None)
                if mail:
                    update_cases_logger.info(f"[score_check.py] get_report: Processing mail: {mail.subject}")
                    failure += process_mail(mail, reports, total_scores, total_confidences, is_malicious, case.id)
                    cortex_job_manager.manage_ai_jobs(case)
            # Process IOCs
            if case.nonFileIocs:
                ioc_data = case.nonFileIocs.get_iocs()
                for ioc_type in ["url", "ip", "hash", "domain"]:
                    ioc = ioc_data.get(ioc_type)
                    if ioc:
                        update_cases_logger.info(f"[score_check.py] get_report: Processing {ioc_type}: {ioc}")
                        failure += process_ioc(ioc, ioc_type, reports, total_scores, total_confidences, is_malicious)
            

            # Compute final scores
            calculate_final_scores(total_scores, total_confidences, case)

            # Update case with results
            update_case_results(case, reports, is_malicious, failure)
            save_case_results(case, mail)
            update_kpi_and_user_stats(case)

            # Update MISP
            misp_handler = MISPHandler(primary=True)
            misp_handler.update_misp(case)

            update_cases_logger.info("[score_check.py] get_report: Case report successfully saved.")

        except Exception as e:
            update_cases_logger.error(f"[score_check.py] get_report: Error processing case: {e}", exc_info=True)

    @staticmethod
    def check_allow_list(data_name, data_type):
        """Checks if a given data item is allow_listed."""
        allow_list_result = {"FileAllowList": None, "DomainAllowList": None, "FiletypeAllowList": None}
        try:
            if data_type == "file":
                file = File.objects.filter(file_path=data_name).first()
                if file:
                    if AllowListFile.objects.filter(linked_file_hash=file.linked_hash).exists():
                        allow_list_result["FileAllowList"] = "Safe FW triggered"
                    if AllowListFiletype.objects.filter(filetype=file.filetype).exists():
                        allow_list_result["FiletypeAllowList"] = "Safe FTW triggered"
            elif data_type == "url":
                domain = CortexAnalyzer.get_domain(data_name)
                if domain and AllowListDomain.objects.filter(domain__value=domain).exists():
                    allow_list_result["DomainAllowList"] = "Safe DW triggered"
        except Exception as e:
            update_cases_logger.error(f"Error checking allow_list: {e}")

        return allow_list_result

    @staticmethod
    def create_report(summary, full, analyzer_name, data_name, data_type, case_id=None):
        """Creates and processes an analysis report."""
        update_cases_logger.info(f"[cortex_analyzers.py] create_report: start function. ({analyzer_name})")

        # Map normalized analyzer names to their respective classes.
        analyzer_classes = {
            "googlesafebrowsing": AnalyzerGoogleSafeBrowsing,
            "fileinfo": AnalyzerFileinfo,
            "virustotal": AnalyzerVT,
            "misp": AnalyzerMISP,
            "otxquery": AnalyzerOTXQuery,
            "urlscan": AnalyzerUrlscan,
            "urlhaus": AnalyzerURLhaus,
            "abuseipdb": AnalyzerAbuseIPDB,
            "crowdsec": AnalyzerCrowdsec,
            "circlhashlookup": AnalyzerCIRCLHashLookup,
            "dshield": AnalyzerDShield,
            "maxmind": AnalyzerMaxMind,
            "mnemonic": AnalyzerMN_PDNS,
            "zscaler": AnalyzerZscaler,
            "stopforumspam": AnalyzerSFS,
            "hashdd": AnalyzerHashdd,
            "yara": AnalyzerYaraSuspicious,
            "yaratasp": AnalyzerYaraTasp,
            "mailheader": AnalyzerMailHeader,
            "ai": AnalyzerAI,
            # Add other mappings as necessary.
        }

        # Normalize analyzer_name: remove patterns like "_<digit>_<digit>" and use the first part in lowercase.
        normalized_name = re.sub(r"_\d_\d", "", analyzer_name).split("_")[0].lower()
        analyzer_class = analyzer_classes.get(normalized_name, BaseAnalyzer)

        try:
            analyzer = analyzer_class(summary, full, data_name, analyzer_name, data_type, case_id)
            response = analyzer.process()
            return response
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] create_report: Error processing report: {e}")
            return {
                "analyzer_name": analyzer_name,
                "data": data_name,
                "score": 0,
                "confidence": 0,
                "category": [],
                "level": "unknown",
                "details": {}
            }
        finally:
            update_cases_logger.debug("[cortex_analyzers.py] create_report: end function.")


class Analyzers:
    @staticmethod
    def analyze_taxonomy(summary, response, analyzer_name):
        """
        Analyzes taxonomies and updates the response accordingly.
        """
        try:
            if "taxonomies" in summary:
                update_cases_logger.debug(f"[cortex_analyzers.py] {analyzer_name}: 'taxonomies' found in summary.")
                severity_order = {"safe": 0, "info": 1, "suspicious": 2, "malicious": 3}
                # Ensure 'details' exists.
                if "details" not in response:
                    response["details"] = {}
                for taxonomy in summary["taxonomies"]:
                    taxonomy_value = taxonomy.get("value")
                    taxonomy_level = taxonomy.get("level", "info").lower()
                    update_cases_logger.debug(
                        f"[cortex_analyzers.py] {analyzer_name}: processing taxonomy with value '{taxonomy_value}' and level '{taxonomy_level}'."
                    )

                    current_level = response.get("level", "info").lower()
                    if severity_order.get(taxonomy_level, 0) > severity_order.get(current_level, 0):
                        update_cases_logger.debug(
                            f"[cortex_analyzers.py] {analyzer_name}: updating level from {current_level} to {taxonomy_level}."
                        )
                        response["level"] = taxonomy_level

                    if "category" not in response:
                        response["category"] = []
                    if taxonomy_value and taxonomy_value not in response["category"]:
                        response["category"].append(taxonomy_value)

                    # Merge taxonomy detail using its predicate as a key.
                    predicate = taxonomy.get("predicate")
                    if predicate:
                        response["details"][predicate] = taxonomy_value

                    response["score"], response["confidence"] = Analyzers.get_level_score_confidence(response["level"])
            else:
                update_cases_logger.debug(f"[cortex_analyzers.py] {analyzer_name}: 'taxonomies' not found in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] {analyzer_name}: error processing taxonomies: {e}")
        return response

    @staticmethod
    def get_level_score_confidence(level):
        """
        Returns the score and confidence for a given level.
        """
        if level == "malicious" or level == "dangerous":
            return 10, 10
        elif level == "suspicious":
            return 7, 7
        elif level == "info":
            return 5, 5
        elif level == "safe":
            return 0, 10
        else:
            return 0, 0

    @staticmethod
    def analyze_results(full, response, analyzer_name, category_key="threat"):
        """
        Analyzes results in the full report and updates the response accordingly.
        """
        try:
            if full and "results" in full and isinstance(full["results"], list):
                update_cases_logger.debug(f"[cortex_analyzers.py] {analyzer_name}: processing full report results.")
                response.setdefault("details", {})
                response.setdefault("category", [])
                for element in full["results"]:
                    # If element is a dictionary, process normally.
                    if isinstance(element, dict):
                        threat = element.get(category_key)
                        if threat and threat not in response["category"]:
                            response["category"].append(threat)
                        # Merge any additional element details into response["details"].
                        for k, v in element.items():
                            if k not in response["details"]:
                                response["details"][k] = v
                    # Otherwise, if the element is not a dict (e.g., a string), handle accordingly.
                    else:
                        threat = element
                        if threat and threat not in response["category"]:
                            response["category"].append(threat)
                        # Save raw result details in a dedicated key.
                        response["details"].setdefault("raw_results", []).append(threat)
            else:
                update_cases_logger.debug(f"[cortex_analyzers.py] {analyzer_name}: full report is empty or 'results' key missing.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] {analyzer_name}: error analyzing full report: {e}")
        return response

    @staticmethod
    def analyze_whitelist(response, whitelist_return):
        """
        Analyzes the whitelist and updates the response accordingly.
        """
        try:
            if whitelist_return is not None:
                response["score"] = 0
                response["confidence"] = 10
                if "category" not in response:
                    response["category"] = []
                response["category"].append(whitelist_return)
                response["level"] = "safe"
                if "details" not in response:
                    response["details"] = {}
                response["details"]["whitelist"] = whitelist_return
            return response
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyze_whitelist: error processing whitelist: {e}")
            return response

    @staticmethod
    def get_analyzer_response(analyzer_name, data_name, level="info", score=5, confidence=5):
        """
        Returns a response dictionary for an analyzer.
        """
        return {
            "analyzer_name": analyzer_name,
            "data": data_name,
            "score": score,
            "confidence": confidence,
            "category": [],
            "level": level,
            "details": {}
        }

class BaseAnalyzer:
    def __init__(self, summary, full, data_name, analyzer_name, type, suspicious_case_id=None):
        self.summary = summary
        self.full = full
        self.data_name = data_name
        self.analyzer_name = analyzer_name
        self.type = type
        self.suspicious_case_id = suspicious_case_id
        # Tenter de récupérer la réponse par défaut via l'analyseur.
        try:
            self.response = Analyzers.get_analyzer_response(self.analyzer_name, self.data_name)
        except Exception as e:
            update_cases_logger.error(
                f"[cortex_analyzers.py] {self.analyzer_name}: Analyseur inconnu ou erreur lors de la récupération de la réponse par défaut : {str(e)}. "
                "Utilisation d'une réponse par défaut."
            )
            self.response = {"level": "info", "details": {}}

    def process(self):
        """
        Traite le rapport de l'analyseur.
        """
        update_cases_logger.debug(f"[cortex_analyzers.py] {self.analyzer_name}: début du traitement.")
        
        # Vérification et application de la whitelist.
        try:
            whitelist_return = CortexAnalyzer.check_allow_list(self.data_name, self.type)
            update_cases_logger.debug(f"[cortex_analyzers.py] whitelist_return: {whitelist_return}.")
            for key, value in whitelist_return.items():
                if value is not None:
                    update_cases_logger.debug(f"[cortex_analyzers.py] {self.analyzer_name}: whitelist déclenchée.")
                    return Analyzers.analyze_whitelist(self.response, value)
        except Exception as e:
            update_cases_logger.error(
                f"[cortex_analyzers.py] {self.analyzer_name}: erreur lors de l'analyse de la whitelist : {str(e)}."
            )
        
        # Analyse de la taxonomie.
        try:
            self.response = Analyzers.analyze_taxonomy(self.summary, self.response, self.analyzer_name)
        except Exception as e:
            update_cases_logger.error(
                f"[cortex_analyzers.py] {self.analyzer_name}: erreur lors de l'analyse de la taxonomie : {str(e)}. "
                "Utilisation d'une analyse par défaut."
            )
        
        # Analyse des résultats complets.
        try:
            self.response = Analyzers.analyze_results(self.full, self.response, self.analyzer_name)
        except Exception as e:
            update_cases_logger.error(
                f"[cortex_analyzers.py] {self.analyzer_name}: erreur lors de l'analyse des résultats : {str(e)}. "
                "Utilisation d'une analyse par défaut."
            )
        
        update_cases_logger.debug(f"[cortex_analyzers.py] {self.analyzer_name}: fin du traitement.")
        return self.response

class AnalyzerAI(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if self.summary:
                # Convert "malscore" to float and use it as the score.
                response["score"] = float(self.summary.get("malscore", 5))
                # Convert "confidence" to float, multiply by 100, and use it as the confidence.
                response["confidence"] = float(self.summary.get("confidence", 0)) * 10
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
                    update_cases_logger.info(f"Chroma client: {chroma_client}")
                except Exception as e:
                    chroma_client = None
                    update_cases_logger.error(f"Error getting chroma client: {e}")

                # Get suspicious collection
                try:
                    if chroma_client:
                        suspicious_collection = get_suspicious_collection(chroma_client)
                        update_cases_logger.info(f"Suspicious collection: {suspicious_collection}")
                except Exception as e:
                    update_cases_logger.error(f"Error getting suspicious collection: {e}")

                alert_id = ''
                sourceRef = ''

                # Check if mail is dangerous
                try:
                    malscore_val = float(response["details"].get("malscore", response.get("score", 5)))
                except Exception:
                    malscore_val = 5.0
                if malscore_val > 6.5:
                    update_cases_logger.info("Mail is considered dangerous")

                    try:
                        self.full["report"]["analyzed_mail_headers"] = parse_and_decode_defaultdict(str(self.full["report"]["analyzed_mail_headers"])) # Decode headers
                    except Exception as e_hdr:
                        update_cases_logger.error(f"Error decoding analyzed_mail_headers: {e_hdr}")

                    # Check if sender domain is in campaign allow_list
                    sender_domain = extract_sender_domain_from_headers(self.full["report"]["analyzed_mail_headers"])
                    is_allow_listed = sender_domain is not None and is_domain_in_campaign_allow_list(sender_domain)

                    if is_allow_listed:
                        update_cases_logger.info(f"Sender domain {sender_domain} is in campaign allow_list, skipping phishing campaign check.")
                        return response
                    else:
                        update_cases_logger.info(f"Sender domain {sender_domain} is not in campaign allow_list, proceeding with phishing campaign check.")
                        THE_HIVE_URL = thehive_config.get('url', '')
                        THE_HIVE_KEY = thehive_config.get('api_key', '')

                        update_cases_logger.info("Checking if phishing is in phishing campaign...")

                        embedding = response["details"]["report"]["email_embedding"]

                        # Get similar mails
                        similar_dangerous_mails = get_similar_dangerous_mails(embedding, suspicious_collection)

                        # Check if phishing campaign
                        phishing_campaign = get_phishing_campaign(similar_dangerous_mails)
                        if phishing_campaign:
                            update_cases_logger.info("Phishing campaign detected!")

                            # Check if alert or case exists
                            try:
                                alert_id = get_most_common_alert_id(phishing_campaign)
                            except Exception as e:
                                update_cases_logger.error(f"Error getting most common alert ID: {e}")
                            if alert_id == '':
                                update_cases_logger.info("Creating an alert...")
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
                                    update_cases_logger.info("Alert created!")
                                    update_cases_logger.info(f"Updating suspicious collection {suspicious_collection}...")
                                    try:
                                        update_suspicious_collection(suspicious_collection, phishing_campaign, alert_id, sourceRef)
                                        update_cases_logger.info("Suspicious collection updated!")
                                    except Exception as e:
                                        update_cases_logger.error(f"Error updating suspicious collection: {e}")
                                except Exception as e:
                                    update_cases_logger.error(f"Error creating alert: {e}")
                                    item = None
                                    item_type = ''
                            else:
                                update_cases_logger.info(f"Getting alert {alert_id}...")
                                try:
                                    item_type, item = get_item_from_id(alert_id, THE_HIVE_URL, THE_HIVE_KEY)
                                    update_cases_logger.info("Got alert!")
                                except Exception as e:
                                    update_cases_logger.error(f"Error getting alert {alert_id}: {e}")
                                    item = None
                                    item_type = ''

                            if isinstance(item, dict) and item["status"] not in ["Duplicate", "False Positive", "Information", "Rejected"]: 
                                suspicious_case_ids = [int(metadata['suspicious_case_id']) for metadata in phishing_campaign['metadatas'][0]] + [self.suspicious_case_id]
                                for suspicious_case_id in suspicious_case_ids:
                                    update_cases_logger.info(f"Adding observables/attachments for {item_type} {suspicious_case_id}...")
                                    try:
                                        case = Case.objects.get(id=suspicious_case_id)
                                        mail_id = str(case.fileOrMail.mail.mail_id)
                                        update_cases_logger.info(f"Mail id for case {suspicious_case_id}: {mail_id}")

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
                                                        update_cases_logger.info(f"Checking object: {obj.object_name} in bucket: {bucket.name}")
                                                        if obj.object_name.startswith(mail_id):
                                                            expected_headers_key = f"{mail_id}/{mail_id}.headers"
                                                            data = minio_client.get_object(bucket.name, expected_headers_key)
                                                            headers = data.read().decode('utf-8')
                                                            update_cases_logger.info(f"Found .headers file in bucket: {bucket.name}")
                                                        if obj.object_name.startswith(mail_id):
                                                            expected_eml_key = f"{mail_id}/{mail_id}.eml"
                                                            data = minio_client.get_object(bucket.name, expected_eml_key)
                                                            eml = data.read().decode('utf-8')
                                                            update_cases_logger.info(f"Found .eml file in bucket: {bucket.name}")
                                                        if obj.object_name.startswith(mail_id):
                                                            expected_txt_key = f"{mail_id}/{mail_id}.txt"
                                                            data = minio_client.get_object(bucket.name, expected_txt_key)
                                                            txt = data.read().decode('utf-8')
                                                            update_cases_logger.info(f"Found .txt file in bucket: {bucket.name}")
                                                        if obj.object_name.startswith(mail_id):
                                                            expected_html_key = f"{mail_id}/{mail_id}.html"
                                                            data = minio_client.get_object(bucket.name, expected_html_key)
                                                            html = data.read().decode('utf-8')
                                                            update_cases_logger.info(f"Found .html file in bucket: {bucket.name}")
                                                except S3Error as e:
                                                    update_cases_logger.error(f"Error listing objects in bucket {bucket.name}: {e}")
                                        try:
                                            add_attachments_to_item(item_type, alert_id, build_mail_attachments_paths(headers, eml, txt, html, suspicious_case_id), THE_HIVE_URL, THE_HIVE_KEY)
                                        except Exception as e:
                                            update_cases_logger.error(f"Error adding attachments for {item_type} {suspicious_case_id}: {e}")
                                        try:
                                            add_observables_to_item(item_type, alert_id, build_mail_observables_from_headers(headers), THE_HIVE_URL, THE_HIVE_KEY)
                                        except Exception as e:
                                            update_cases_logger.error(f"Error adding headers observables for {item_type} {suspicious_case_id}: {e}")
                                        try:
                                            add_observables_to_item(item_type, alert_id, build_mail_observables_from_html(html), THE_HIVE_URL, THE_HIVE_KEY)
                                        except Exception as e:
                                            update_cases_logger.error(f"Error adding HTML observables for {item_type} {suspicious_case_id}: {e}")
                                    except Exception as e:
                                        update_cases_logger.error(f"Error adding observables/attachments for {item_type} {suspicious_case_id}: {e}")
                        else:
                            update_cases_logger.info("No phishing campaign detected.")
                else:
                    update_cases_logger.info("Mail is not considered dangerous")
                update_cases_logger.info("Adding mail to suspicious collection...")
                timestamp = add_to_suspicious_collection(self.full, alert_id, sourceRef, self.suspicious_case_id, suspicious_collection)
                update_cases_logger.info(f"Mail added to suspicious collection with timestamp: {timestamp}")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] AnalyzerAI: error processing report: {e}")
        return response

class AnalyzerFileinfo(BaseAnalyzer):
    def process(self):
        response = super().process()
        best_candidate = None
        details = {}
        # Define severity ordering: higher number means higher severity.
        level_priority = {"safe": 0, "info": 1, "suspicious": 2, "malicious": 3}
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_fileinfo: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "FileInfo":
                        # Record the taxonomy details keyed by predicate.
                        predicate = taxonomy.get("predicate", "unknown")
                        details[predicate] = taxonomy.get("value", "")
                        
                        current_level = taxonomy.get("level", "safe").lower()
                        # Choose the worst level seen so far.
                        if best_candidate is None or level_priority.get(current_level, 0) > level_priority.get(best_candidate, 0):
                            best_candidate = current_level
                if best_candidate is not None:
                    response["level"] = best_candidate
                    response["details"] = details  # Optional: include file info details in the response.
                    response["score"], response["confidence"] = Analyzers.get_level_score_confidence(response["level"])
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_fileinfo: No FileInfo taxonomies found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_fileinfo: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_fileinfo: error analyzing FileInfo taxonomies: {str(e)}.")
        return response

class AnalyzerGoogleSafeBrowsing(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_google_safebrowsing: field 'taxonomies' is in summary.")
                # Default level and details
                level = "safe"
                details = {}
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "Google" and taxonomy.get("predicate") == "Safebrowsing":
                        details[taxonomy.get("predicate", "unknown")] = taxonomy.get("value", "")
                        value = taxonomy.get("value", "")
                        # Extract numeric count from the value string (e.g., "0 match")
                        match = re.search(r'(\d+)', value)
                        count = int(match.group(1)) if match else 0
                        if count > 0:
                            level = "suspicious"
                        else:
                            level = "safe"
                        break  # Exit after processing the relevant taxonomy.
                
                response["level"] = level
                response["details"] = details
                response["score"], response["confidence"] = Analyzers.get_level_score_confidence(response["level"])
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_google_safebrowsing: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_google_safebrowsing: error analyzing Google SafeBrowsing taxonomies: {str(e)}.")
        return response

class AnalyzerVT(BaseAnalyzer):
    def process(self):
        response = super().process()
        best_candidate = None
        # Define severity ordering: higher number means higher severity.
        level_priority = {"safe": 0, "info": 1, "suspicious": 2, "malicious": 3}
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_vt: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "VT" and taxonomy.get("predicate") == "GetReport":
                        value = taxonomy.get("value", "")
                        ratio = None
                        candidate_level = None

                        # Try to compute ratio if value is in "numerator/denominator" format.
                        if "/" in value:
                            parts = value.split("/")
                            if len(parts) == 2:
                                try:
                                    numerator = int(parts[0].strip())
                                    denominator = int(parts[1].strip())
                                    ratio = numerator / denominator if denominator != 0 else 0
                                except ValueError:
                                    update_cases_logger.error(f"[cortex_analyzers.py] analyzer_vt: Could not parse ratio from value: {value}")
                                    ratio = 0
                        else:
                            # Fallback: use regex to extract the first number.
                            match = re.search(r'(\d+)', value)
                            if match:
                                numerator = int(match.group(1))
                                # Using a default denominator of 100 if not provided.
                                ratio = numerator / 100.0
                            else:
                                update_cases_logger.error(f"[cortex_analyzers.py] analyzer_vt: No numeric value found in: {value}")
                                ratio = 0

                        # Determine candidate level based on the computed ratio.
                        if ratio is not None:
                            if ratio >= 0.5:
                                candidate_level = "malicious"
                            elif ratio >= 0.1:
                                candidate_level = "suspicious"
                            else:
                                taxonomy_level = taxonomy.get("level", "safe").lower()
                                candidate_level = taxonomy_level if taxonomy_level in level_priority else "safe"
                        else:
                            candidate_level = taxonomy.get("level", "safe").lower()

                        # Update the best candidate if this taxonomy is more severe.
                        if best_candidate is None or level_priority[candidate_level] > level_priority.get(best_candidate, 0):
                            best_candidate = candidate_level

                if best_candidate is not None:
                    response["level"] = best_candidate
                    response["score"], response["confidence"] = Analyzers.get_level_score_confidence(response["level"])
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_vt: No VT GetReport taxonomies found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_vt: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_vt: error analyzing VT taxonomies: {str(e)}.")
        return response

class AnalyzerAbuseIPDB(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_abuseipdb: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "AbuseIPDB" and taxonomy.get("predicate") == "Records":
                        # Get the record count from the taxonomy; expected to be numeric
                        count = taxonomy.get("value", 0)
                        try:
                            count = int(count)
                        except Exception:
                            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_abuseipdb: could not convert value to int: {count}")
                            count = 0
                        
                        # Determine level based on count
                        if count > 10:
                            level = "malicious"
                        elif count > 0:
                            level = "suspicious"
                        else:
                            level = "safe"
                        
                        response["level"] = level
                        response["details"] = {"Records": count}
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Stop after processing the relevant taxonomy
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_abuseipdb: No AbuseIPDB Records taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_abuseipdb: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_abuseipdb: error analyzing AbuseIPDB taxonomies: {str(e)}.")
        return response

class AnalyzerCrowdsec(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_crowdsec: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "Crowdsec" and taxonomy.get("predicate") == "Threat":
                        # Retrieve the taxonomy's value and declared level.
                        level = taxonomy.get("level", "safe").lower()
                        details = {"Crowdsec Threat": taxonomy.get("value", "")}
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_crowdsec: No Crowdsec Threat taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_crowdsec: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_crowdsec: error analyzing Crowdsec taxonomies: {str(e)}.")
        return response

class AnalyzerCIRCLHashLookup(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_circlhashlookup: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "CIRCLHashlookup" and taxonomy.get("predicate") == "Result":
                        result_value = taxonomy.get("value", "").lower()
                        # Determine level based on the result value.
                        if result_value in ["unknown", "unkown"]:
                            level = "info"
                        elif result_value == "found":
                            # Adjust the level if a result is found (could be "suspicious" or "malicious")
                            level = "suspicious"
                        else:
                            level = taxonomy.get("level", "info").lower()
                        
                        response["level"] = level
                        response["details"] = {"CIRCLHashlookup": taxonomy.get("value", "")}
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_circlhashlookup: No CIRCLHashlookup taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_circlhashlookup: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_circlhashlookup: error analyzing CIRCLHashlookup taxonomies: {str(e)}.")
        return response

class AnalyzerDShield(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_dshield: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "DShield" and taxonomy.get("predicate") == "Score":
                        value = taxonomy.get("value", "")
                        # Use regex to extract the count, attack, and threatfeed numbers.
                        pattern = r'(\d+)\s*count\(s\)\s*/\s*(\d+)\s*attack\(s\)\s*/\s*(\d+)\s*threatfeed\(s\)'
                        match = re.search(pattern, value, re.IGNORECASE)
                        if match:
                            count_num = int(match.group(1))
                            attacks_num = int(match.group(2))
                            threatfeeds_num = int(match.group(3))
                        else:
                            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_dshield: could not parse DShield score from value: {value}")
                            count_num = attacks_num = threatfeeds_num = 0

                        # The declared taxonomy level is "safe" in this example.
                        level = taxonomy.get("level", "safe").lower()

                        # Build details using both the taxonomy value and additional full data.
                        details = {
                            "DShield Score": value,
                            "IP": self.full.get("ip", ""),
                            "Count": self.full.get("count", 0),
                            "Attacks": self.full.get("attacks", 0),
                            "Threatfeeds Count": self.full.get("threatfeedscount", 0),
                            "Reputation": self.full.get("reputation", "")
                        }
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching DShield taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_dshield: No DShield Score taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_dshield: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_dshield: error analyzing DShield taxonomies: {str(e)}.")
        return response

class AnalyzerMaxMind(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_maxmind: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "MaxMind" and taxonomy.get("predicate") == "Location":
                        # Get the declared level and location value from the taxonomy.
                        level = taxonomy.get("level", "info").lower()
                        location_value = taxonomy.get("value", "")
                        
                        # Build details using both the taxonomy and the full geolocation data.
                        details = {"MaxMind Location": location_value}
                        if self.full:
                            details["City"] = self.full.get("city", {})
                            details["Continent"] = self.full.get("continent", {})
                            details["Country"] = self.full.get("country", {})
                            details["Location"] = self.full.get("location", {})
                            details["Registered Country"] = self.full.get("registered_country", {})
                            details["Represented Country"] = self.full.get("represented_country", {})
                            details["Subdivisions"] = self.full.get("subdivisions", {})
                            details["Traits"] = self.full.get("traits", {})
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching MaxMind taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_maxmind: No MaxMind Location taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_maxmind: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_maxmind: error analyzing MaxMind taxonomies: {str(e)}.")
        return response

class AnalyzerMN_PDNS(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_mn_pdns: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "MN_PDNS" and taxonomy.get("predicate") == "Public":
                        # Extract the numeric value and level from the taxonomy.
                        pdns_value = taxonomy.get("value", 0)
                        level = taxonomy.get("level", "info").lower()
                        
                        # Build details from the taxonomy and the full findings.
                        details = {"MN_PDNS Public Value": pdns_value}
                        if self.full and "findings" in self.full:
                            findings = self.full["findings"]
                            details["Findings Count"] = findings.get("count", 0)
                            details["Data"] = findings.get("data", [])
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_mn_pdns: No MN_PDNS Public taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_mn_pdns: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_mn_pdns: error analyzing MN_PDNS taxonomies: {str(e)}.")
        return response

class AnalyzerOTXQuery(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_otxquery: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "OTX" and taxonomy.get("predicate") == "Pulses":
                        value = taxonomy.get("value", "0")
                        try:
                            count = int(value)
                        except Exception:
                            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_otxquery: could not convert value to int: {value}")
                            count = 0
                        details = {"Pulses": count}
                        
                        # Determine level based on the pulse count.
                        if count == 0:
                            level = "safe"
                        elif count >= 50:
                            level = "malicious"
                        elif count >= 100:
                            level = "suspicious"
                        else:
                            level = "info"
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching OTX taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_otxquery: No OTX Pulses taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_otxquery: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_otxquery: error analyzing OTX taxonomies: {str(e)}.")
        return response

class AnalyzerUrlscan(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_urlscan: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "urlscan.io" and taxonomy.get("predicate") == "Search":
                        value = taxonomy.get("value", "")
                        # Extract numeric count from the value string (e.g., "0 result")
                        match = re.search(r'(\d+)', value)
                        count = int(match.group(1)) if match else 0
                        details = {"urlscan.io Search Results": count}
                        
                        # If count > 0 then mark as suspicious, otherwise safe.
                        if count > 0:
                            level = "suspicious"
                        else:
                            level = "safe"
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_urlscan: No urlscan.io Search taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_urlscan: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_urlscan: error analyzing urlscan.io taxonomies: {str(e)}.")
        return response

class AnalyzerURLhaus(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_urlhaus: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "URLhaus" and taxonomy.get("predicate") == "Search":
                        value = taxonomy.get("value", "")
                        details = {"URLhaus Search": value}
                        
                        # Determine level based on the value.
                        if "no results" in value.lower():
                            level = "safe"
                        else:
                            # Attempt to extract a numeric count if available.
                            match = re.search(r'(\d+)', value)
                            if match:
                                count = int(match.group(1))
                                # Example threshold: if count > 0, mark as suspicious.
                                level = "suspicious" if count > 0 else "safe"
                            else:
                                # Fallback to the provided taxonomy level.
                                level = taxonomy.get("level", "info").lower()
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching URLhaus taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_urlhaus: No URLhaus Search taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_urlhaus: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_urlhaus: error analyzing URLhaus taxonomies: {str(e)}.")
        return response

class AnalyzerCFApp(BaseAnalyzer):
    def process(self):
        return super().process()

class AnalyzerZscaler(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_zscaler: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "Zscaler" and taxonomy.get("predicate") == "Classification":
                        # Get the classification value and the declared level
                        classification_value = taxonomy.get("value", "").strip()
                        level = taxonomy.get("level", "safe").lower()
                        
                        # Build details from both taxonomy and full response details
                        details = {"Zscaler Classification": classification_value}
                        if self.full:
                            details["URL"] = self.full.get("url", "")
                            details["URL Classifications"] = self.full.get("urlClassifications", [])
                            details["URL Classifications with Security Alert"] = self.full.get("urlClassificationsWithSecurityAlert", [])
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_zscaler: No Zscaler Classification taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_zscaler: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_zscaler: error analyzing Zscaler taxonomies: {str(e)}.")
        return response

class AnalyzerSFS(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_sfs: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "SFS" and taxonomy.get("predicate") == "ip":
                        level = taxonomy.get("level", "info").lower()
                        details = {"SFS ip": taxonomy.get("value", "")}
                        # Incorporate additional details from the full data.
                        if self.full:
                            details["Full IP"] = self.full.get("value", "")
                            details["Frequency"] = self.full.get("frequency", 0)
                            details["Appears"] = self.full.get("appears", False)
                            details["ASN"] = self.full.get("asn", "")
                            details["Country"] = self.full.get("country", "")
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching SFS taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_sfs: No SFS ip taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_sfs: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_sfs: error analyzing SFS taxonomies: {str(e)}.")
        return response

class AnalyzerThreatGridOnPrem(BaseAnalyzer):
    def process(self):
        return super().process()

class AnalyzerMISP(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_misp: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "MISP" and taxonomy.get("predicate") == "Search":
                        value = taxonomy.get("value", "0")
                        # Extract numeric count from the value string (e.g., "4 event(s)" -> 4)
                        match = re.search(r'(\d+)', str(value))
                        count = int(match.group(1)) if match else 0
                        details = {"MISP Events": count}
                        level = taxonomy.get("level", "0")
                        # Determine level based on event count thresholds.
                        if level == "0":
                            if count >= 4:
                                level = "malicious"
                            elif count > 0:
                                level = "suspicious"
                            else:
                                level = "safe"
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching MISP taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_misp: No MISP Search taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_misp: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_misp: error analyzing MISP taxonomies: {str(e)}.")
        return response

class AnalyzerHashdd(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_hashdd: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "Hashdd" and taxonomy.get("predicate") == "knownlevel":
                        value = taxonomy.get("value", "").strip().lower()
                        # If the known level is reported as "unknown", we set level to "info"
                        if value == "unknown":
                            level = "info"
                        else:
                            # Fallback: use the provided taxonomy level if available, defaulting to "info"
                            level = taxonomy.get("level", "info").lower()
                        
                        response["level"] = level
                        response["details"] = {"knownlevel": taxonomy.get("value", "")}
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_hashdd: No Hashdd knownlevel taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_hashdd: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_hashdd: error analyzing Hashdd taxonomies: {str(e)}.")
        return response

class AnalyzerMailHeader(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            # Process taxonomies from the summary.
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_mailheader: 'taxonomies' found in summary.")
                severity_order = {"safe": 0, "info": 1, "suspicious": 2, "malicious": 3}
                # Ensure details and category are initialized.
                response.setdefault("details", {})
                response.setdefault("category", [])
                
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "MailHeader":
                        predicate = taxonomy.get("predicate")
                        value = taxonomy.get("value")
                        level = taxonomy.get("level", "info").lower()

                        # Add taxonomy detail (using the predicate as the key).
                        if predicate:
                            response["details"][predicate] = value

                        # Also add the taxonomy value to the category list if not already present.
                        if value and value not in response["category"]:
                            response["category"].append(value)

                        # Update response level if taxonomy level is more severe.
                        current_level = response.get("level", "info").lower()
                        if severity_order.get(level, 0) > severity_order.get(current_level, 0):
                            response["level"] = level
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_mailheader: 'taxonomies' not found in summary.")

            # Merge additional details from the full report.
            if self.full:
                response.setdefault("details", {})
                response["details"]["full_malscore"] = self.full.get("malscore")
                response["details"]["full_confidence"] = self.full.get("confidence")
                response["details"]["full_malfamily"] = self.full.get("malfamily")
                response["details"]["report"] = self.full.get("report")

            # Finally, update score and confidence based on the current level.
            response["score"], response["confidence"] = Analyzers.get_level_score_confidence(response["level"])
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_mailheader: error processing MailHeader: {str(e)}")
        return response

class AnalyzerYaraSuspicious(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_yara_suspicious: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "Yara" and taxonomy.get("predicate") == "Match":
                        value = taxonomy.get("value", "")
                        # Extract the number of rule matches (e.g., "3 rule(s)" -> 3)
                        match = re.search(r'(\d+)', value)
                        rule_count = int(match.group(1)) if match else 0
                        
                        # Use the taxonomy's declared level (e.g., "malicious")
                        level = taxonomy.get("level", "safe").lower()
                        
                        # Prepare details including the rule count and full Yara results if available.
                        details = {"Yara Rule Matches": rule_count}
                        if self.full and "results" in self.full:
                            details["Yara Full Results"] = self.full["results"]
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_yara_suspicious: No Yara Match taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_yara_suspicious: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_yara_suspicious: error analyzing Yara taxonomies: {str(e)}.")
        return response

class AnalyzerYaraTasp(BaseAnalyzer):
    def process(self):
        response = super().process()
        try:
            if "taxonomies" in self.summary:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_yara: field 'taxonomies' is in summary.")
                for taxonomy in self.summary["taxonomies"]:
                    if taxonomy.get("namespace") == "Yara" and taxonomy.get("predicate") == "Match":
                        value = taxonomy.get("value", "")
                        # Extract the number of rule matches (e.g., "3 rule(s)" -> 3)
                        match = re.search(r'(\d+)', value)
                        rule_count = int(match.group(1)) if match else 0
                        
                        # Use the taxonomy's declared level (e.g., "malicious")
                        level = taxonomy.get("level", "safe").lower()
                        
                        # Prepare details including the rule count and full Yara results if available.
                        details = {"Yara Rule Matches": rule_count}
                        if self.full and "results" in self.full:
                            details["Yara Full Results"] = self.full["results"]
                        
                        response["level"] = level
                        response["details"] = details
                        response["score"], response["confidence"] = Analyzers.get_level_score_confidence(level)
                        break  # Process only the first matching taxonomy.
                else:
                    update_cases_logger.debug("[cortex_analyzers.py] analyzer_yara: No Yara Match taxonomy found.")
            else:
                update_cases_logger.debug("[cortex_analyzers.py] analyzer_yara: field 'taxonomies' is not in summary.")
        except Exception as e:
            update_cases_logger.error(f"[cortex_analyzers.py] analyzer_yara: error analyzing Yara taxonomies: {str(e)}.")
        return response