import json
import logging

from thehive4py import TheHiveApi
from minio import Minio
from minio.error import S3Error
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from mail_feeder.models import MailArtifact, MailAttachment

from .utils import generate_ref, build_mail_attachments_paths

logger = logging.getLogger(__name__)
update_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")
TEMPLATES_DIR = Path(__file__).parent.parent / "send_mail/templates"


CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)
minio_config = config.get("minio", {})
mail_config = config.get('mail', {})
thehive_config = config.get('thehive', {})

class ChallengeToTheHiveService:
    def __init__(self, case, recipient, subject):
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)

        self.case = case
        self.challenger = case.reporter
        self.challenger_firstname = case.reporter.first_name
        self.challenger_lastname = case.reporter.last_name
        self.challenger_email = case.reporter.email
        self.challenger_groups = [g.name for g in case.reporter.groups.all()]
        self.recipient = recipient
        self.subject = subject

        self.template = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html"])
        ).get_template("challenge_email.jinja2")

    def _context(self) -> dict:
        mail = getattr(getattr(self.case, "fileOrMail", None), "mail", None)

        artifacts = [
            {
                "label": a.artifact_type,
                "score": a.artifact_score,
                "confidence": a.artifact_confidence,
            }
            for a in MailArtifact.objects.filter(mail=mail)
        ]

        attachments = [
            a.file.file_path.name
            for a in MailAttachment.objects.filter(mail=mail)
        ]

        result_color = {
            "Dangerous": "#EF3340",
            "Suspicious": "#FFAA4D",
            "Safe": "#00AB84",
            "Inconclusive": "#0085CA",
        }.get(self.case.results, "#000")

        mail_cfg = self.config["mail"]

        return {
            "subject": self.subject,
            "recipient_name": self.recipient,
            "company": mail_cfg["group"],
            "global_team": mail_cfg["global"],
            "logos": mail_cfg["logos"],
            "urls": {
                "portal": mail_cfg["submissions"],
                "glossary": mail_cfg["glossary"],
                "inquiry": mail_cfg["inquiry"],
                "global": mail_cfg["global_url"],
            },
            "inquiry_text": mail_cfg["inquiry_text"],
            "socials": [
                {
                    "name": name,
                    "url": url,
                    "logo": mail_cfg["social_logos"][name],
                }
                for name, url in mail_cfg["socials"].items()
            ],
            "challenger": {
                "firstname": self.challenger.first_name,
                "lastname": self.challenger.last_name,
                "email": self.challenger.email,
                "groups": ", ".join(
                    g.name for g in self.challenger.groups.all()
                ) or "No group",
            },
            "case": {
                "id": self.case.id,
                "score": self.case.score,
                "confidence": self.case.confidence,
                "result": self.case.results,
                "result_color": result_color,
                "ai": {
                    "category": self.case.categoryAI,
                    "result": self.case.resultsAI,
                    "score": round(self.case.scoreAI),
                    "confidence": round(self.case.confidenceAI),
                },
            },
            "mail": {
                "subject": getattr(mail, "subject", "N/A"),
                "from": getattr(mail, "mail_from", "N/A"),
            },
            "artifacts": artifacts,
            "attachments": attachments,
        }

    def send(self) -> None:
        html = self.template.render(self._context())

        msg = MIMEMultipart("alternative")
        msg["From"] = self.config["mail"]["username"]
        msg["To"] = self.recipient
        msg["Subject"] = self.subject
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(
            self.config["mail"]["server"],
            self.config["mail"]["port"]
        ) as smtp:
            smtp.send_message(msg)


    def send_to_thehive(self):
        """
        Send an alert to TheHive from a challenge.

        Creates an alert in TheHive with the details of the challenge,
        including case, mail, challenger info, and related artifacts/attachments.
        """
        def safe(value, default=None):
            return value if value not in (None, "") else default

        # Challenger information
        challenger = {
            "firstname": safe(self.challenger_firstname),
            "lastname": safe(self.challenger_lastname),
            "email": safe(self.challenger_email),
            "groups": safe(self.challenger_groups, [])
        }

        case = self.case
        mail = getattr(getattr(case, "fileOrMail", None), "mail", None)

        # TheHive connection parameters
        THE_HIVE_URL = thehive_config.get("url", "")
        THE_HIVE_KEY = thehive_config.get("api_key", "")


        if not mail:
            fileormail = case.fileOrMail
            if fileormail:
                file = fileormail.file
                if file:
                  create_alert_from_challenge_without_mail(
                      api_url=THE_HIVE_URL,
                      api_key=THE_HIVE_KEY,
                      case=case,
                      file=file,
                      ioc=file.linked_hash.value,
                      datatype="hash",
                      challenger=challenger
                  )
            else:
              nonfileiocs = case.nonFileIocs
              if nonfileiocs:
                  url = nonfileiocs.url
                  ip = nonfileiocs.ip
                  hash = nonfileiocs.hash

                  if url:
                      create_alert_from_challenge_without_mail(
                          api_url=THE_HIVE_URL,
                          api_key=THE_HIVE_KEY,
                          case=case,
                          file=None,
                          ioc=url.address,
                          datatype="url",
                          challenger=challenger
                      )
                  if ip:
                      create_alert_from_challenge_without_mail(
                          api_url=THE_HIVE_URL,
                          api_key=THE_HIVE_KEY,
                          case=case,
                          file=None,
                          ioc=ip.address,
                          datatype="ip",
                          challenger=challenger
                      )
                  if hash:
                      create_alert_from_challenge_without_mail(
                          api_url=THE_HIVE_URL,
                          api_key=THE_HIVE_KEY,
                          case=case,
                          file=None,
                          ioc=hash.value,
                          datatype="hash",
                          challenger=challenger
                      )
            return  # Exit if there's no mail associated with the case
        # Prepare artifacts mapping
        artifact_type_map = {
            "ip": lambda a: (safe(getattr(getattr(a, "artifactIsIp", None), "ip.address", None)), "ip"),
            "url": lambda a: (safe(getattr(getattr(a, "artifactIsUrl", None), "url.address", None)), "url"),
            "mailaddress": lambda a: (safe(getattr(getattr(a, "artifactIsMailAddress", None), "mail_address.address", None)), "mail"),
            "domain": lambda a: (safe(getattr(getattr(a, "artifactIsDomain", None), "domain.value", None)), "domain"),
            "hash": lambda a: (safe(getattr(getattr(a, "artifactIsHash", None), "hash.value", None)), "hash")
        }

        artifact_summary = []
        for artifact in MailArtifact.objects.filter(mail=mail):
            if artifact:
                artifact_type = safe(artifact.artifact_type, "").lower()
                if artifact_type in artifact_type_map:
                    data, dtype = artifact_type_map[artifact_type](artifact)
                    if data:  # Only add non-empty data
                        artifact_summary.append((data, dtype))

        # Prepare attachments
        attachments_summary = [
            safe(att.file.file_path.name)
            for att in MailAttachment.objects.filter(mail=mail)
            if safe(att.file.file_path.name)
        ]

        # Send alert to TheHive
        try:
            create_alert_from_challenge(
                api_url=THE_HIVE_URL,
                api_key=THE_HIVE_KEY,
                case=case,
                mail=mail,
                challenger=challenger,
                artifact_summary=artifact_summary,
                attachments_summary=attachments_summary
            )
        except Exception as e:
            # You might want to use logging instead of print in production
            print(f"[ERROR] Failed to create TheHive alert for case #{safe(case.id)}: {e}")

def create_alert_from_challenge_without_mail(api_url, api_key, case, file, ioc, datatype, challenger):
    """
    Create an alert in TheHive when a user challenges the result of a case.

    :param api_url: TheHive API base URL
    :param api_key: TheHive API key
    :param case: Case object containing analysis results
    :param file: File object related to the case
    :param ioc: IOC object related to the case
    :param challenger: dict with keys 'firstname', 'lastname', 'email'
    :param artifact_summary: list of tuples (value, type) for extracted artifacts
    :param attachments_summary: list of filenames for attachments
    """
    api = TheHiveApi(url=api_url, apikey=api_key, verify=thehive_config.get('the_hive_verify_ssl', ''))
    ticket_id = generate_ref()
    # Construction du titre
    if file:
      title = f"Challenge: Case #{case.id} - File {file.file_path.name}"
    else:
      title = f"Challenge: Case #{case.id} - IOC {str(ioc)} ({datatype})"
    # Description complète
    description = (
        f"# {challenger.get('firstname', 'N/A')} {challenger.get('lastname', 'N/A')} "
        f"({challenger.get('email', 'N/A')}) has challenged the result of case #{case.id}.\n\n"
        f"|Value|Description|\n"
        f"|---|---|\n"
        f"|Case Score|{getattr(case, 'score', 'N/A')}|\n"
        f"|Case Confidence|{getattr(case, 'confidence', 'N/A')}|\n"
        f"|Results|{getattr(case, 'results', 'N/A')}|"
    )
    # Création des observables
    observables = [
        {"data": ioc, "dataType": datatype}
    ]
    # Envoi de l'alerte
    return api.alert.create(
        alert={
            "type": "user_challenge",
            "source": "suspicious",
            "sourceRef": ticket_id,
            "title": title,
            "description": description,
            "observables": observables,
            "severity": 1,  # 1=Low, 2=Medium, 3=High
            "tlp": 1,
            "pap": 1,
            "tags": ["challenge", "file_ioc", "suspicious"],
            "customFields": {
                "tha-id": ticket_id
            }
        }
    )

def create_alert_from_challenge(api_url, api_key, case, mail, challenger, artifact_summary=None, attachments_summary=None):
    """
    Create an alert in TheHive when a user challenges the result of a case.

    :param api_url: TheHive API base URL
    :param api_key: TheHive API key
    :param case: Case object containing analysis results
    :param mail: Mail object related to the case
    :param challenger: dict with keys 'firstname', 'lastname', 'email'
    :param artifact_summary: list of tuples (value, type) for extracted artifacts
    :param attachments_summary: list of filenames for attachments
    """
    api = TheHiveApi(url=api_url, apikey=api_key, verify=thehive_config.get('the_hive_verify_ssl', ''))
    eml = ""
    # Utilitaires pour gérer les valeurs None
    def safe(value, default="N/A"):
        return value if value not in (None, "") else default
    ticket_id = generate_ref()
    # Construction du titre
    title = f"Challenge: Case #{safe(case.id)} - {safe(getattr(mail, 'subject', None), 'No Subject')}"

    # Tableau récapitulatif
    summary_table = f"""|Value|Description|
|---|---|
|Mail Subject|{safe(getattr(mail, 'subject', None))}|
|From|{safe(getattr(mail, 'mail_from', None))}|
|Case Score|{safe(getattr(case, 'score', None))}|
|Case Confidence|{safe(getattr(case, 'confidence', None))}|
|AI Suggestion|{safe(getattr(case, 'categoryAI', None))} / {safe(getattr(case, 'resultsAI', None))} (Score: {round(getattr(case, 'scoreAI', 0))}, Confidence: {round(getattr(case, 'confidenceAI', 0))})|
|Results|{safe(getattr(case, 'results', None))}|"""

    # Liste des artefacts
    artifacts_section = "\n".join(
        f"- {val[0].replace('.', '[.]')} ({val[1]})" for val in (artifact_summary or [])
    ) or "No artifacts found."

    # Liste des pièces jointes
    attachments_section = "\n".join(
        f"- {val}" for val in (attachments_summary or [])
    ) or "No attachments found."

    # Description complète
    description = (
        f"# {safe(challenger.get('firstname'))} {safe(challenger.get('lastname'))} "
        f"({safe(challenger.get('email'))}) has challenged the result of case #{safe(case.id)}.\n\n"
        f"{summary_table}\n\n"
        f"## Extracted Artifacts:\n{artifacts_section}\n\n"
        f"## Attachments:\n{attachments_section}"
    )
    mail_id = safe(getattr(mail, 'mail_id', None), 'unknown-mail-id')
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
                    if obj.object_name.startswith(mail_id):
                        expected_eml_key = f"{mail_id}/{mail_id}.eml"
                        data = minio_client.get_object(bucket.name, expected_eml_key)
                        eml = data.read().decode('utf-8')
            except S3Error as e:
                print(f"Error listing objects in bucket {bucket.name}: {e}")
    tmp_path = build_mail_attachments_paths(eml, ticket_id)
    
    attachment_key = ticket_id
    attachment_map = {attachment_key: tmp_path}
    # Création des observables
    observables = [
        {"data": val[0], "dataType": val[1]}
        for val in (artifact_summary or [])
    ] + [
        {"dataType": "file", "attachment": attachment_key} if tmp_path else {}
    ]
    # Envoi de l'alerte
    return api.alert.create(
        alert={
            "type": "user_challenge",
            "source": "suspicious",
            "sourceRef": ticket_id,
            "title": title,
            "description": description,
            "observables": observables,
            "severity": 1,  # 1=Low, 2=Medium, 3=High
            "tlp": 1,
            "pap": 1,
            "tags": ["challenge", "mail", "suspicious"],
            "customFields": {
                "tha-id": ticket_id
            }
        }, attachment_map=attachment_map
    )
