import json
import smtplib
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from jinja2 import Environment, FileSystemLoader, select_autoescape

CONFIG_PATH = "/app/settings.json"
TEMPLATES_DIR = Path(__file__).parent / "templates"


class AcknowledgementEmailService:
    def __init__(self) -> None:
        self.config = self._load_config()
        self.template = self._load_template()

    @staticmethod
    def _load_config() -> dict:
        with open(CONFIG_PATH) as f:
            return json.load(f)["mail"]

    @staticmethod
    def _load_template():
        env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html", "xml"]),
        )
        return env.get_template("acknowledgement_email.jinja2")

    def render_html(self, recipient: str, recipient_name: str) -> str:
        return self.template.render(
            subject="Suspicious – Submission Registered",
            recipient_name=recipient_name,
            company_name=self.config["group"],
            company_logo=self.config["logos"]["company"],
            acknowledge_logo=self.config["logos"]["acknowledge"],
            portal_url=self.config["submissions"],
            glossary_url=self.config["glossary"],
            inquiry_url=self.config["inquiry"],
            inquiry_text=self.config["inquiry_text"],
            global_team=self.config["global"],
            global_url=self.config["global_url"],
            socials=[
                {
                    "name": name,
                    "url": url,
                    "logo": self.config["social_logos"][name],
                }
                for name, url in self.config["socials"].items()
            ],
        )

    def send(self, recipient: str, recipient_name: str) -> None:
        html = self.render_html(recipient, recipient_name)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Suspicious – Submission Registered"
        msg["From"] = self.config["username"]
        msg["To"] = recipient
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(self.config["server"], self.config["port"]) as smtp:
            smtp.send_message(msg)
