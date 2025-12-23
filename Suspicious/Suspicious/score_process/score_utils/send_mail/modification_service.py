import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

CONFIG_PATH = "/app/settings.json"
TEMPLATES_DIR = Path(__file__).parent / "templates"


class ModificationEmailService:
    def __init__(self, subject, sender, recipient, recipient_name, case):
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)["mail"]

        self.subject = subject
        self.sender = sender
        self.recipient = recipient
        self.recipient_name = recipient_name
        self.case = case

        self.template = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html"]),
        ).get_template("modification_email.jinja2")

    def _case_type(self) -> str:
        fm = self.case.fileOrMail
        nf = self.case.nonFileIocs

        if fm and fm.mail:
            return "e-mail"
        if fm and fm.file:
            return "file"
        if nf:
            return "ioc"
        return "item"

    def _result_block(self, case_type: str) -> dict:
        portal = self.config["submissions"]
        cert_url = self.config.get("security")
        cert_msg = self.config.get("security_msg")

        mapping = {
            "Dangerous": {
                "color": "#FF0000",
                "text": f"As a conclusion, this {case_type} has been revised as dangerous*.",
                "desc": (
                    f"Do not open files or links. If interaction occurred, report to "
                    f"<a href='{cert_url}' target='_blank'>{cert_msg}</a>."
                ),
            },
            "Suspicious": {
                "color": "#FF9A00",
                "text": f"As a conclusion, this {case_type} has been revised as most likely suspicious*.",
                "desc": "As a precaution, avoid interaction.",
            },
            "Inconclusive": {
                "color": "#00A4E9",
                "text": f"As a conclusion, this {case_type} has been revised as inconclusive*.",
                "desc": "The analysis could not determine safety.",
            },
            "Safe": {
                "color": "#5EC27F",
                "text": f"As a conclusion, this {case_type} has been revised as most likely safe*.",
                "desc": "You may proceed while remaining vigilant.",
            },
        }

        return mapping.get(self.case.results, mapping["Inconclusive"])

    def _context(self) -> dict:
        case_type = self._case_type()
        result = self._result_block(case_type)

        return {
            "subject": self.subject,
            "recipient_name": self.recipient_name,
            "company": self.config["group"],
            "global_team": self.config["global"],
            "logos": self.config["logos"],
            "urls": {
                "portal": self.config["submissions"],
                "glossary": self.config["glossary"],
                "inquiry": self.config["inquiry"],
                "global": self.config["global_url"],
            },
            "inquiry_text": self.config["inquiry_text"],
            "socials": [
                {
                    "name": name,
                    "url": url,
                    "logo": self.config["social_logos"][name],
                }
                for name, url in self.config["socials"].items()
            ],
            "case": {
                "id": self.case.id,
            },
            "result": {
                "color": result["color"],
                "text": result["text"],
                "description": result["desc"],
            },
        }

    def send(self) -> None:
        html = self.template.render(self._context())

        msg = MIMEMultipart("alternative")
        msg["From"] = self.sender
        msg["To"] = self.recipient
        msg["Subject"] = self.subject
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(
            self.config["server"],
            self.config["port"]
        ) as smtp:
            smtp.send_message(msg)
