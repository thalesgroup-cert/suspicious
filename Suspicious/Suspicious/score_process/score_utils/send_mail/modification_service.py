# mail_service/modification_service.py
import json
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .send_email_service import SendMailService
from .models import ModificationMailServiceConfigSocial
from .email_logo import resolve_logo
from .email_theme import resolve_email_theme
from .social_logos import SOCIAL_LOGOS

import os as _os_cfg
CONFIG_PATH = _os_cfg.environ.get("SUSPICIOUS_CONFIG_PATH", "/app/settings.json")
TEMPLATES_DIR = Path(__file__).parent / "templates"

# Maps case.results (internal Django value) to the semantic color key
_RESULT_TO_COLOR_KEY = {
    "Dangerous":    "color_dangerous",
    "Suspicious":   "color_suspicious",
    "Safe":         "color_safe",
    "Inconclusive": "color_inconclusive",
    "Unchallenged": "color_inconclusive",
    "AllowListed":  "color_safe",
    "Failure":      "color_failure",
}

_RESULT_LABEL = {
    "Dangerous":    "Dangerous",
    "Suspicious":   "Suspicious",
    "Safe":         "Safe",
    "Inconclusive": "Inconclusive",
    "Unchallenged": "Unchallenged",
    "AllowListed":  "Allow-listed",
    "Failure":      "Analysis failed",
}

_RESULT_GUIDANCE = {
    "Dangerous": (
        "Do not open any files or click any links. "
        "If you have already interacted with this item, report it to your security team immediately."
    ),
    "Suspicious": (
        "As a precaution, avoid any further interaction with this item "
        "until a full review has been completed."
    ),
    "Safe": (
        "The item has been assessed as safe. You may proceed, but remain vigilant — "
        "no automated analysis is conclusive on its own."
    ),
    "Inconclusive": (
        "The revised analysis could not reach a definitive conclusion. "
        "Treat the item with caution until a further review is completed."
    ),
    "Unchallenged": (
        "The result stands as assessed. No challenge was submitted within the allowed window."
    ),
    "AllowListed": (
        "This item is on the organisation allow-list and has been cleared automatically."
    ),
    "Failure": (
        "The analysis process encountered an error. "
        "Our team has been notified and will review the case manually."
    ),
}


class ModificationEmailService:
    def __init__(
        self,
        subject: str,
        sender: str,
        recipient: str,
        recipient_name: str,
        case,
        profile=None,           # UserProfile — drives theme + semantic colors
    ):
        with open(CONFIG_PATH) as f:
            self.config = json.load(f).get("email", {})

        self.subject       = subject
        self.sender        = str(sender)
        self.recipient     = str(recipient)
        self.recipient_name = recipient_name
        self.case          = case
        self.theme_ctx     = resolve_email_theme(profile)

        env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.template = env.get_template("modification_email.jinja2")

    # ── case helpers ───────────────────────────────────────────────────────

    def _case_type(self) -> str:
        fm = getattr(self.case, "fileOrMail", None)
        nf = getattr(self.case, "nonFileIocs", None)
        if fm and getattr(fm, "mail", None):
            return "email"
        if fm and getattr(fm, "file", None):
            return "file"
        if nf:
            return "indicator"
        return "item"

    def _build_case_context(self) -> dict:
        raw_result = getattr(self.case, "results", None) or "Failure"
        cert_url   = self.config.get("links", {}).get("security_contact", "")
        cert_msg   = self.config.get("links", {}).get("security_text", "contact us")

        # Dangerous gets an extra contact CTA — plain text, no | safe needed
        contact_cta = (
            f"If you have already interacted with this item, "
            f"contact {cert_msg} at {cert_url} immediately."
            if raw_result == "Dangerous" and cert_url
            else ""
        )

        return {
            "id":             getattr(self.case, "id", ""),
            "type":           self._case_type(),
            "result":         raw_result,
            "result_label":   _RESULT_LABEL.get(raw_result, raw_result),
            "result_color":   self.theme_ctx.get(
                _RESULT_TO_COLOR_KEY.get(raw_result, "color_inconclusive"),
                "#94A3B8",
            ),
            "result_guidance": _RESULT_GUIDANCE.get(
                raw_result,
                "Please review the case details on the portal."
            ),
            "contact_cta": contact_cta,
        }

    # ── rendering ──────────────────────────────────────────────────────────

    def render_html(self, subject: str, recipient_name: str) -> str:
        links = self.config.get("links", {})
        content = self.config.get("content", {})

        return self.template.render(
            # Content
            subject=subject,
            recipient_name=recipient_name,
            company_name=content.get("team_name"),
            company_logo_svg=resolve_logo(self.config.get("logos", {}).get("company-svg")),
            company_logo_png=resolve_logo(self.config.get("logos", {}).get("company-png")),
            final_logo=resolve_logo(self.config.get("logos", {}).get("final")),
            portal_url=links.get("submissions")+f"?q={getattr(self.case, 'id', '')}&open={getattr(self.case, 'id', '')}",
            glossary_url=links.get("glossary"),
            inquiry_url=links.get("inquiry"),
            inquiry_text=links.get("inquiry_text"),
            global_team=content.get("global_domain"),
            global_url=content.get("website"),
            socials=[
                ModificationMailServiceConfigSocial(
                    name=social,
                    url=self.config.get("socials", {}).get(social, f"https://{social}.com"),
                    logo_svg=SOCIAL_LOGOS.get("svgs", {}).get(social),
                    logo_png=SOCIAL_LOGOS.get("pngs", {}).get(social),
                )
                for social in self.config.get("socials", {})
                if SOCIAL_LOGOS.get("svgs", {}).get(social) or SOCIAL_LOGOS.get("pngs", {}).get(social)
            ],
            # Case context — all plain strings, no raw HTML
            case=self._build_case_context(),
            # Theme palette + semantic colors
            **self.theme_ctx,
        )

    # ── send ───────────────────────────────────────────────────────────────

    def _send_action(self, user: str, user_infos: str, subject: str) -> None:
        html = self.render_html(recipient_name=user_infos, subject=subject)

        smtp = self.config.get("smtp", {})
        send_mail_service = SendMailService(
            host=smtp.get("server", ""),
            port=smtp.get("port", 587),
            login=smtp.get("username", ""),
            password=smtp.get("password", ""),
        )
        send_mail_service.connect()
        if smtp.get("tls"):
            send_mail_service.start_tls()
        send_mail_service.login()
        send_mail_service.publish_email(
            subject=subject,
            sender=self.sender,
            recipient=user,
            html=html,
        )
        send_mail_service.close()