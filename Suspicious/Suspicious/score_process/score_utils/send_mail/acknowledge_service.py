from .models import AcknowledgeMailServiceConfigSocial
from .send_email_service import SendMailService
from .email_theme import THEME_PALETTES, resolve_semantic_colors
from .email_logo import resolve_logo
from .social_logos import SOCIAL_LOGOS
from .utils import load_email_template

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
        # Acknowledgement mails always use the light palette, regardless of
        # the recipient's UI theme. Semantic colors still follow the profile.
        self.theme_ctx = {
            **THEME_PALETTES["light"],
            **resolve_semantic_colors(profile),
        }

    @staticmethod
    def _load_config() -> dict:
        from .utils import load_email_config
        return load_email_config()

    @staticmethod
    def _load_template():
        return load_email_template("acknowledgement_email.jinja2")

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
        SendMailService.send_html(
            self.config.get("smtp", {}),
            sender=self.sender,
            recipient=user,
            subject=subject,
            html=html,
        )