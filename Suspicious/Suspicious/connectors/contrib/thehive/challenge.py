import logging
from pathlib import Path

from thehive4py import TheHiveApi
from minio.error import S3Error
from jinja2 import Environment, FileSystemLoader, select_autoescape
from mail_feeder.models import Mail

from common.clients import get_s3_client
from .utils import generate_ref, build_mail_attachments_paths
from score_process.score_utils.send_mail.social_logos import SOCIAL_LOGOS
from score_process.score_utils.send_mail.send_email_service import SendMailService

logger = logging.getLogger(__name__)
TEMPLATES_DIR = Path(__file__).parent.parent.parent.parent / "score_process/score_utils/send_mail/templates"

def _thehive_config() -> dict:
    from settings.config import get_section
    return get_section("integrations.thehive")



def _certificate_path():
    return _thehive_config().get("certificate_path") or True

_RESULT_COLOR = {
    "Dangerous":   "#EF3340",
    "Suspicious":  "#FFAA4D",
    "Safe":        "#00AB84",
    "Inconclusive":"#0085CA",
}

_CHALLENGE_MAIL_PREFETCH = (
    "mail_attachments__file",
    "mail_artifacts__artifactIsIp__ip",
    "mail_artifacts__artifactIsUrl__url",
    "mail_artifacts__artifactIsHash__hash",
    "mail_artifacts__artifactIsDomain__domain",
    "mail_artifacts__artifactIsMailAddress__mail_address",
)


def _refetch_mail_with_prefetch(mail):
    return Mail.objects.prefetch_related(*_CHALLENGE_MAIL_PREFETCH).get(pk=mail.pk)


def _safe(value, default=None):
    return value if value not in (None, "") else default


def _safe_round(value, default=0):
    try:
        return round(value)
    except (TypeError, ValueError):
        return default


class ChallengeToTheHiveService:

    def __init__(self, case, recipient: str, subject: str) -> None:
        from suspicious._config_common import load_settings
        self.config = load_settings()

        self.case      = case
        self.recipient = recipient
        self.subject   = subject

        self.challenger          = case.reporter
        self.challenger_firstname = case.reporter.first_name
        self.challenger_lastname  = case.reporter.last_name
        self.challenger_email     = case.reporter.email
        self.challenger_groups    = [g.name for g in case.reporter.groups.all()]

        self.template = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html"]),
        ).get_template("challenge_email.jinja2")

    # ── config helpers ─────────────────────────────────────────────────────

    def _mail_cfg(self) -> dict:
        return self.config.get("email", {})

    def _smtp_cfg(self) -> dict:
        mail_cfg = self._mail_cfg()
        return self.config.get("smtp", self.config.get("mail", mail_cfg))

    # ── context ────────────────────────────────────────────────────────────

    def _build_socials(self) -> list[dict]:
        mail_cfg = self._mail_cfg()
        return [
            {
                "name":     social,
                "url":      self.config.get("socials", {}).get(social, f"https://{social}.com"),
                "logo_svg": SOCIAL_LOGOS.get("svgs", {}).get(social),
                "logo_png": SOCIAL_LOGOS.get("pngs", {}).get(social),
            }
            for social in mail_cfg.get("socials", {})
            if SOCIAL_LOGOS.get("svgs", {}).get(social) or SOCIAL_LOGOS.get("pngs", {}).get(social)
        ]

    def _build_case_context(self, mail) -> dict:
        mail = _refetch_mail_with_prefetch(mail)

        artifacts = [
            {
                "label":      a.artifact_type,
                "score":      a.artifact_score,
                "confidence": a.artifact_confidence,
            }
            for a in mail.mail_artifacts.all()
        ]

        attachments = [
            a.file.file_path.name
            for a in mail.mail_attachments.all()
        ]

        return {
            "id":         self.case.id,
            "score":      self.case.score,
            "confidence": self.case.confidence,
            "result":     self.case.results,
            "result_color": _RESULT_COLOR.get(self.case.results, "#000"),
            "ai": {
                "category":   self.case.category_ai,
                "result":     self.case.results_ai,
                "score":      _safe_round(self.case.score_ai),
                "confidence": _safe_round(self.case.confidence_ai),
            },
            "artifacts":   artifacts,
            "attachments": attachments,
        }

    def _context(self) -> dict:
        mail     = getattr(getattr(self.case, "fileOrMail", None), "mail", None)
        mail_cfg = self._mail_cfg()

        return {
            "subject":        self.subject,
            "recipient_name": self.recipient,
            "company":        mail_cfg.get("content", {}).get("team_name"),
            "global_team":    mail_cfg.get("content", {}).get("global_domain"),
            "logos":          mail_cfg.get("logos", {}),
            "urls": {
                "portal":   mail_cfg.get("links", {}).get("submissions"),
                "glossary": mail_cfg.get("links", {}).get("glossary"),
                "inquiry":  mail_cfg.get("links", {}).get("inquiry"),
                "global":   mail_cfg.get("content", {}).get("website"),
            },
            "inquiry_text": mail_cfg.get("links", {}).get("inquiry_text"),
            "socials":      self._build_socials(),
            "challenger": {
                "firstname": self.challenger.first_name,
                "lastname":  self.challenger.last_name,
                "email":     self.challenger.email,
                "groups":    ", ".join(g.name for g in self.challenger.groups.all()) or "No group",
            },
            "case": self._build_case_context(mail),
            "mail": {
                "subject": getattr(mail, "subject",   "N/A"),
                "from":    getattr(mail, "mail_from", "N/A"),
            },
        }

    # ── send ───────────────────────────────────────────────────────────────

    def send(self) -> None:
        html     = self.template.render(self._context())
        smtp_cfg = self._smtp_cfg()
        sender   = smtp_cfg.get("username") or smtp_cfg.get("from", "")

        service = SendMailService(
            host=smtp_cfg["server"],
            port=smtp_cfg["port"],
            login=smtp_cfg.get("username", ""),
            password=smtp_cfg.get("password", ""),
        )
        service.connect()
        try:
            if smtp_cfg.get("password"):
                service.start_tls()
                service.login()
            service.publish_email(
                subject=self.subject, sender=sender,
                recipient=self.recipient, html=html,
            )
        finally:
            service.close()

    # ── TheHive ────────────────────────────────────────────────────────────

    def send_to_thehive(self) -> None:
        THE_HIVE_URL = _thehive_config().get("url", "")
        THE_HIVE_KEY = _thehive_config().get("api_key", "")

        challenger = {
            "firstname": _safe(self.challenger_firstname),
            "lastname":  _safe(self.challenger_lastname),
            "email":     _safe(self.challenger_email),
            "groups":    _safe(self.challenger_groups, []),
        }

        case = self.case
        mail = getattr(getattr(case, "fileOrMail", None), "mail", None)

        if not mail:
            self._send_thehive_without_mail(THE_HIVE_URL, THE_HIVE_KEY, case, challenger)
            return

        self._send_thehive_with_mail(THE_HIVE_URL, THE_HIVE_KEY, case, mail, challenger)

    def _send_thehive_without_mail(self, api_url, api_key, case, challenger) -> None:
        fileormail = case.fileOrMail
        if fileormail:
            file = fileormail.file
            if file:
                create_alert_from_challenge_without_mail(
                    api_url=api_url, api_key=api_key,
                    case=case, file=file,
                    ioc=file.linked_hash.value, datatype="hash",
                    challenger=challenger,
                )
            return

        nonfileiocs = case.nonFileIocs
        if not nonfileiocs:
            return

        for ioc_attr, datatype in [("url", "url"), ("ip", "ip"), ("hash", "hash")]:
            ioc_obj = getattr(nonfileiocs, ioc_attr, None)
            if ioc_obj:
                ioc_value = getattr(ioc_obj, "address" if ioc_attr != "hash" else "value", None)
                if ioc_value:
                    create_alert_from_challenge_without_mail(
                        api_url=api_url, api_key=api_key,
                        case=case, file=None,
                        ioc=ioc_value, datatype=datatype,
                        challenger=challenger,
                    )

    def _send_thehive_with_mail(self, api_url, api_key, case, mail, challenger) -> None:
        artifact_type_map = {
            "ip":          lambda a: (_safe(getattr(getattr(a, "artifactIsIp",          None), "ip.address",           None)), "ip"),
            "url":         lambda a: (_safe(getattr(getattr(a, "artifactIsUrl",         None), "url.address",          None)), "url"),
            "mailaddress": lambda a: (_safe(getattr(getattr(a, "artifactIsMailAddress", None), "mail_address.address", None)), "mail"),
            "domain":      lambda a: (_safe(getattr(getattr(a, "artifactIsDomain",      None), "domain.value",         None)), "domain"),
            "hash":        lambda a: (_safe(getattr(getattr(a, "artifactIsHash",        None), "hash.value",           None)), "hash"),
        }

        mail = _refetch_mail_with_prefetch(mail)

        artifact_summary = []
        for artifact in mail.mail_artifacts.all():
            artifact_type = _safe(artifact.artifact_type, "").lower()
            if artifact_type in artifact_type_map:
                data, dtype = artifact_type_map[artifact_type](artifact)
                if data:
                    artifact_summary.append((data, dtype))

        attachments_summary = [
            _safe(att.file.file_path.name)
            for att in mail.mail_attachments.all()
            if _safe(att.file.file_path.name)
        ]

        try:
            create_alert_from_challenge(
                api_url=api_url, api_key=api_key,
                case=case, mail=mail,
                challenger=challenger,
                artifact_summary=artifact_summary,
                attachments_summary=attachments_summary,
            )
        except Exception as e:
            logger.error(f"Failed to create TheHive alert for case #{_safe(case.id)}: {e}")


# ── standalone alert helpers ────────────────────────────────────────────────

def create_alert_from_challenge_without_mail(api_url, api_key, case, file, ioc, datatype, challenger):
    api       = TheHiveApi(url=api_url, apikey=api_key, verify=_certificate_path())
    ticket_id = generate_ref()

    title = (
        f"Challenge: Case #{case.id} - File {file.file_path.name}"
        if file else
        f"Challenge: Case #{case.id} - IOC {ioc} ({datatype})"
    )

    description = (
        f"# {challenger.get('firstname', 'N/A')} {challenger.get('lastname', 'N/A')} "
        f"({challenger.get('email', 'N/A')}) has challenged the result of case #{case.id}.\n\n"
        f"|Value|Description|\n|---|---|\n"
        f"|Case Score|{getattr(case, 'score', 'N/A')}|\n"
        f"|Case Confidence|{getattr(case, 'confidence', 'N/A')}|\n"
        f"|Results|{getattr(case, 'results', 'N/A')}|\n"
        f"|Proposed Verdict|{getattr(case, 'challenge_proposed_result', None) or 'N/A'}|\n\n"
        f"## Challenge Reason:\n{getattr(case, 'challenge_reason', None) or 'No reason provided.'}"
    )

    return api.alert.create(alert={
        "type":        "user_challenge",
        "source":      "suspicious",
        "sourceRef":   ticket_id,
        "title":       title,
        "description": description,
        "observables": [{"data": ioc, "dataType": datatype}],
        "severity": 1, "tlp": 1, "pap": 1,
        "tags":         ["challenge", "file_ioc", "suspicious"],
        "customFields": {"tha-id": ticket_id},
    })


def create_alert_from_challenge(api_url, api_key, case, mail, challenger,
                                artifact_summary=None, attachments_summary=None):
    api       = TheHiveApi(url=api_url, apikey=api_key, verify=_certificate_path())
    ticket_id = generate_ref()
    eml       = ""

    def safe(v, default="N/A"):
        return v if v not in (None, "") else default

    title = f"Challenge: Case #{safe(case.id)} - {safe(getattr(mail, 'subject', None), 'No Subject')}"

    summary_table = (
        f"|Value|Description|\n|---|---|\n"
        f"|Mail Subject|{safe(getattr(mail, 'subject', None))}|\n"
        f"|From|{safe(getattr(mail, 'mail_from', None))}|\n"
        f"|Case Score|{safe(getattr(case, 'score', None))}|\n"
        f"|Case Confidence|{safe(getattr(case, 'confidence', None))}|\n"
        f"|AI Suggestion|{safe(getattr(case, 'category_ai', None))} / {safe(getattr(case, 'results_ai', None))} "
        f"(Score: {_safe_round(getattr(case, 'score_ai', None))}, "
        f"Confidence: {_safe_round(getattr(case, 'confidence_ai', None))})|\n"
        f"|Results|{safe(getattr(case, 'results', None))}|\n"
        f"|Proposed Verdict|{safe(getattr(case, 'challenge_proposed_result', None))}|"
    )

    artifacts_section = "\n".join(
        f"- {v[0].replace('.', '[.]')} ({v[1]})" for v in (artifact_summary or [])
    ) or "No artifacts found."

    attachments_section = "\n".join(
        f"- {v}" for v in (attachments_summary or [])
    ) or "No attachments found."

    description = (
        f"# {safe(challenger.get('firstname'))} {safe(challenger.get('lastname'))} "
        f"({safe(challenger.get('email'))}) has challenged the result of case #{safe(case.id)}.\n\n"
        f"{summary_table}\n\n"
        f"## Challenge Reason:\n{safe(getattr(case, 'challenge_reason', None), 'No reason provided.')}\n\n"
        f"## Extracted Artifacts:\n{artifacts_section}\n\n"
        f"## Attachments:\n{attachments_section}"
    )

    mail_id = safe(getattr(mail, "mail_id", None), "unknown-mail-id")
    minio_client = get_s3_client()

    for bucket in minio_client.list_buckets():
        if bucket.name.endswith(f"-{mail_id.split('-')[0]}"):
            try:
                for obj in minio_client.list_objects(bucket.name, prefix=mail_id, recursive=False):
                    if obj.object_name.startswith(mail_id):
                        data = minio_client.get_object(bucket.name, f"{mail_id}/{mail_id}.eml")
                        eml  = data.read().decode("utf-8")
            except S3Error as e:
                logger.error(f"Error listing objects in bucket {bucket.name}: {e}")

    tmp_path = build_mail_attachments_paths(eml, ticket_id)

    observables = [{"data": v[0], "dataType": v[1]} for v in (artifact_summary or [])]
    attachment_map = {}
    if tmp_path:
        observables.append({"dataType": "file", "attachment": ticket_id})
        attachment_map[ticket_id] = tmp_path

    return api.alert.create(
        alert={
            "type":        "user_challenge",
            "source":      "suspicious",
            "sourceRef":   ticket_id,
            "title":       title,
            "description": description,
            "observables": observables,
            "severity": 1, "tlp": 1, "pap": 1,
            "tags":         ["challenge", "mail", "suspicious"],
            "customFields": {"tha-id": ticket_id},
        },
        attachment_map=attachment_map,
    )