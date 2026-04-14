# mail_service/acknowledge_service.py
import json
from pathlib import Path
from .models import AcknowledgeMailServiceConfigSocial
from jinja2 import Environment, FileSystemLoader, select_autoescape
from .send_email_service import SendMailService
from .email_theme import resolve_email_theme
from .email_logo import resolve_logo
from .social_logos import SOCIAL_LOGOS

CONFIG_PATH = "/app/settings.json"
TEMPLATES_DIR = Path(__file__).parent / "templates"

class AcknowledgementEmailService:
    SUBJECT = "Suspicious – Submission Registered"

    def __init__(
        self,
        *,
        sender: str | None = None,
        profile=None,
    ) -> None:
        self.config = self._load_config()
        self.sender = str(sender or self.config.get("smtp", {}).get("username"))
        self.template = self._load_template()
        # Resolve theme + semantic colors from the recipient's profile.
        # Falls back to graphite defaults when profile is None.
        self.theme_ctx = resolve_email_theme(profile)

    @staticmethod
    def _load_config() -> dict:
        with open(CONFIG_PATH) as f:
            return json.load(f).get("email", {})

    @staticmethod
    def _load_template():
        env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html", "xml"]),
        )
        return env.get_template("acknowledgement_email.jinja2")

    # ── rendering ──────────────────────────────────────────────────────────

    def render_html(self, recipient_name: str, subject: str) -> str:
        return self.template.render(
            # Content
            subject=subject,
            recipient_name=recipient_name,
            company_name=self.config.get("content", {}).get("team_name"),
            company_logo_svg=resolve_logo(self.config.get("logos", {}).get("company-svg")),
            company_logo_png=resolve_logo(self.config.get("logos", {}).get("company-png")),
            acknowledge_logo=resolve_logo(self.config.get("logos", {}).get("suspicious")),
            portal_url=self.config.get("links", {}).get("submissions"),
            glossary_url=self.config.get("links", {}).get("glossary"),
            inquiry_url=self.config.get("links", {}).get("inquiry"),
            inquiry_text=self.config.get("links", {}).get("inquiry_text"),
            global_team=self.config.get("content", {}).get("global_domain"),
            global_url=self.config.get("content", {}).get("website"),
            socials=[
                AcknowledgeMailServiceConfigSocial(
                    name=social,
                    url=self.config.get("socials", {}).get(social, f"https://{social}.com"),
                    logo_svg=SOCIAL_LOGOS.get("svgs", {}).get(social),
                    logo_png=SOCIAL_LOGOS.get("pngs", {}).get(social),
                )
                for social in self.config.get("socials", {})
                if SOCIAL_LOGOS.get("svgs", {}).get(social) or SOCIAL_LOGOS.get("pngs", {}).get(social)
            ],
            # Theme — all palette + semantic color variables
            **self.theme_ctx,
        )

    # ── send ───────────────────────────────────────────────────────────────

    def _send_action(self, user: str, user_infos: str, subject: str) -> None:
        html = self.render_html(recipient_name=user_infos, subject=subject)

        send_mail_service = SendMailService(
            host=self.config.get("smtp", {}).get("server", {}),
            port=self.config.get("smtp", {}).get("port", {}),
            login=self.config.get("smtp", {}).get("username", {}),
            password=self.config.get("smtp", {}).get("password", {}),
        )

        send_mail_service.connect()
        if self.config.get("smtp", {}).get("tls", {}):
            send_mail_service.start_tls()
        send_mail_service.login()
        send_mail_service.publish_email(
            subject=subject,
            sender=self.sender,
            recipient=user,
            html=html,
        )
        send_mail_service.close()