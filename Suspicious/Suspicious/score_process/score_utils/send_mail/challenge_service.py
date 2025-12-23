import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from mail_feeder.models import MailArtifact, MailAttachment

CONFIG_PATH = "/app/settings.json"
TEMPLATES_DIR = Path(__file__).parent / "templates"


class ChallengeEmailService:
    def __init__(self, case, challenger, recipient, subject):
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)

        self.case = case
        self.challenger = challenger
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
