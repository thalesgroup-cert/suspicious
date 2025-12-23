import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

CONFIG_PATH = "/app/settings.json"
TEMPLATES_DIR = Path(__file__).parent / "templates"


class FinalEmailService:
    def __init__(self, subject: str, sender: str, recipient: str, case, recipient_name: str):
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)["mail"]

        self.subject = subject
        self.sender = sender
        self.recipient = recipient
        self.recipient_name = recipient_name
        self.case = case

        self.template = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html"])
        ).get_template("final_email.jinja2")

    def _case_metadata(self) -> dict:
        if self.case.fileOrMail:
            if self.case.fileOrMail.mail:
                mail = self.case.fileOrMail.mail
                return {
                    "type": "mail",
                    "subject": mail.subject,
                    "sender": mail.mail_from,
                    "recipient": mail.to,
                }
            if self.case.fileOrMail.file:
                return {
                    "type": "file",
                    "subject": self.case.id,
                    "sender": self.case.fileOrMail.file.file_path.name,
                    "recipient": None,
                }

        if self.case.nonFileIocs:
            ioc = self.case.nonFileIocs
            value = ioc.ip or ioc.url or ioc.hash
            return {
                "type": "ioc",
                "subject": self.case.id,
                "sender": value,
                "recipient": None,
            }

        return {
            "type": "unknown",
            "subject": self.case.id,
            "sender": "N/A",
            "recipient": None,
        }

    def _result_block(self, case_type: str) -> dict:
        online = self.config["submissions"]
        cert_url = self.config.get("security")
        cert_msg = self.config.get("security_msg")

        mapping = {
            "Dangerous": {
                "color": "#FF0000",
                "text": f"As a conclusion, this {case_type} has been assessed as dangerous*.",
                "desc": (
                    f"If applicable, do not open files or click links. "
                    f"If interaction already occurred, report to "
                    f"<a href='{cert_url}' target='_blank'>{cert_msg}</a>."
                ),
            },
            "Suspicious": {
                "color": "#FF9A00",
                "text": f"As a conclusion, this {case_type} has been assessed as most likely suspicious*.",
                "desc": (
                    f"As a precaution, avoid interaction. "
                    f"You may challenge the result <a href='{online}' target='_blank'>here</a>."
                ),
            },
            "Safe": {
                "color": "#5EC27F",
                "text": f"As a conclusion, this {case_type} has been assessed as most likely safe*.",
                "desc": "You may proceed safely, while remaining vigilant.",
            },
            "Inconclusive": {
                "color": "#0084BD",
                "text": "Unfortunately, the investigations were inconclusive*.",
                "desc": (
                    f"The analysis could not determine safety. "
                    f"You may challenge the result <a href='{online}' target='_blank'>here</a>."
                ),
            },
            "Failure": {
                "color": "#000000",
                "text": "The analysis failed to provide a result.",
                "desc": (
                    f"Please verify manually or challenge the result "
                    f"<a href='{online}' target='_blank'>here</a>."
                ),
            },
        }

        return mapping.get(self.case.results, mapping["Failure"])

    def _context(self) -> dict:
        case_meta = self._case_metadata()
        result = self._result_block(case_meta["type"])

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
                **case_meta,
                "result_color": result["color"],
                "result_text": result["text"],
                "result_description": result["desc"],
            },
        }

    def send(self) -> None:
        html = self.template.render(self._context())

        msg = MIMEMultipart("alternative")
        msg["From"] = self.sender
        msg["To"] = self.recipient
        msg["Subject"] = self.subject
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(self.config["server"], self.config["port"]) as smtp:
            smtp.send_message(msg)
