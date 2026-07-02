from urllib.parse import urlparse

from .models import FinalMailServiceConfigSocial
from .send_email_service import SendMailService
from .email_theme import THEME_PALETTES, resolve_semantic_colors
from .email_logo import resolve_logo
from case_handler.models import CaseChallengeToken
from .social_logos import SOCIAL_LOGOS
from .utils import load_email_template

# Maps case.results (internal Django value) to the semantic color key in the
# email theme context — so the verdict badge always uses the user's own colors.
_RESULT_TO_COLOR_KEY = {
    "Dangerous":    "color_dangerous",
    "Suspicious":   "color_suspicious",
    "Safe":         "color_safe",
    "Inconclusive": "color_inconclusive",
    "Unchallenged": "color_inconclusive",  # closest semantic match
    "AllowListed":  "color_safe",
    "Failure":      "color_failure",
}

# Human-readable label shown in the email subject line of the verdict badge
_RESULT_LABEL = {
    "Dangerous":    "Dangerous",
    "Suspicious":   "Suspicious",
    "Safe":         "Safe",
    "Inconclusive": "Inconclusive",
    "Unchallenged": "Unchallenged",
    "AllowListed":  "Allow-listed",
    "Failure":      "Analysis failed",
}

# One-line guidance sentence per result
_RESULT_GUIDANCE = {
    "Dangerous": (
        "Do not open any files or click any links associated with this item. "
        "Contact your security team immediately if you have already interacted with it."
    ),
    "Suspicious": (
        "Exercise caution. Avoid interacting with any files or links until "
        "further investigation has been completed."
    ),
    "Safe": (
        "No threats were detected. You may proceed, but remain vigilant — "
        "no analysis is 100 % conclusive."
    ),
    "Inconclusive": (
        "Our analyzers could not reach a definitive verdict. "
        "Treat the item with caution until a human review is completed."
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


class FinalEmailService:

    def __init__(
        self,
        *,
        case,
        sender: str,
        recipient,
        recipient_name: str,
        profile=None,           # UserProfile — drives theme + semantic colors
    ) -> None:
        self.case          = case
        self.sender        = str(sender)
        self.recipient     = str(recipient)
        self.recipient_name = recipient_name
        self.config        = self._load_config()
        self.template      = self._load_template()
        # Verdict mails always use the light palette, regardless of the
        # recipient's UI theme. Semantic colors still follow the profile.
        self.theme_ctx     = {
            **THEME_PALETTES["light"],
            **resolve_semantic_colors(profile),
        }

    @staticmethod
    def _load_config() -> dict:
        from .utils import load_email_config
        return load_email_config()

    @staticmethod
    def _load_template():
        return load_email_template("final_email.jinja2")

    # ── rendering ──────────────────────────────────────────────────────────

    def render_html(self, subject: str) -> str:
        return self.template.render(
            # ── Content ───────────────────────────────────────────────────
            subject=subject,
            recipient_name=self.recipient_name,
            company_name=self.config.get("content", {}).get("team_name"),
            company_logo_svg=resolve_logo(self.config.get("logos", {}).get("company-svg")),
            company_logo_png=resolve_logo(self.config.get("logos", {}).get("company-png")),
            final_logo=resolve_logo(self.config.get("logos", {}).get("suspicious")),
            portal_url=self.config.get("links", {}).get("submissions")+f"?q={self.case.id}&open={self.case.id}",
            glossary_url=self.config.get("links", {}).get("glossary"),
            inquiry_url=self.config.get("links", {}).get("inquiry"),
            inquiry_text=self.config.get("links", {}).get("inquiry_text"),
            global_team=self.config.get("content", {}).get("global_domain"),
            global_url=self.config.get("content", {}).get("website"),
            socials=[
                FinalMailServiceConfigSocial(
                    name=social,
                    url=self.config.get("socials", {}).get(social, f"https://{social}.com"),
                    logo_svg=SOCIAL_LOGOS.get("svgs", {}).get(social),
                    logo_png=SOCIAL_LOGOS.get("pngs", {}).get(social),
                )
                for social in self.config.get("socials", {})
                if SOCIAL_LOGOS.get("svgs", {}).get(social) or SOCIAL_LOGOS.get("pngs", {}).get(social)
            ],
            # ── Case metadata ─────────────────────────────────────────────
            case=self._build_case_context(),
            # ── Theme (all palette + semantic color vars) ──────────────────
            **self.theme_ctx,
        )

    # ── case helpers ───────────────────────────────────────────────────────

    def _build_case_context(self) -> dict:
        """
        Merge artifact metadata with verdict data into a single dict
        that the template can use without any logic.
        """
        meta    = self._case_metadata()
        verdict = self._verdict_context()
        return {**meta, **verdict}

    def _case_metadata(self) -> dict:
        fom = getattr(self.case, "fileOrMail", None)

        if fom and getattr(fom, "mail", None):
            mail = fom.mail
            return {
                "type":      "Email",
                "subject":   getattr(mail, "subject", ""),
                "sender":    getattr(mail, "mail_from", ""),
                "recipient": getattr(mail, "to", None),
            }

        if fom and getattr(fom, "file", None):
            file_field = getattr(fom.file, "file_path", None)
            file_name  = getattr(file_field, "name", None) or str(fom.file_id)
            return {
                "type":      "File",
                "subject":   file_name,
                "sender":    None,
                "recipient": None,
            }

        ioc = getattr(self.case, "nonFileIocs", None)
        if ioc:
            if getattr(ioc, "url", None):
                kind  = "URL"
                value = getattr(ioc.url, "address", str(ioc.url_id))
            elif getattr(ioc, "ip", None):
                kind  = "IP address"
                value = getattr(ioc.ip, "address", str(ioc.ip_id))
            elif getattr(ioc, "hash", None):
                kind  = "Hash"
                value = getattr(ioc.hash, "value", str(ioc.hash_id))
            else:
                kind  = "Indicator"
                value = str(self.case.id)
            return {
                "type":      kind,
                "subject":   value,
                "sender":    None,
                "recipient": None,
            }

        return {
            "type":      "Submission",
            "subject":   str(self.case.id),
            "sender":    None,
            "recipient": None,
        }

    def _verdict_context(self) -> dict:
        """
        Build verdict fields that reference theme color keys by name
        rather than hardcoding hex values.  The template resolves the
        actual color through the theme_ctx variables.
        """
        raw_result = getattr(self.case, "results", None) or "Failure"

        return {
            # The internal result string e.g. "Dangerous", "Safe"
            "result":       raw_result,
            # The CSS variable name in the theme context that holds this
            # result's color — e.g. "color_dangerous", "color_safe"
            # Template uses: style="color:{{ case.result_color_var | theme_color }}"
            # We just pass the name; template does: {{ theme_color_for(case.result) }}
            # Simpler: pass the resolved hex directly so template stays logic-free.
            "result_color": self.theme_ctx.get(
                _RESULT_TO_COLOR_KEY.get(raw_result, "color_inconclusive"),
                "#94A3B8",
            ),
            "result_label": _RESULT_LABEL.get(raw_result, raw_result),
            "result_guidance": _RESULT_GUIDANCE.get(
                raw_result,
                "Please review the case details on the portal."
            ),
            # AI fields — shown as reference chips
            "result_ai":        getattr(self.case, "results_ai",  None),
            "category_ai":      getattr(self.case, "category_ai", None),
            "score":            getattr(self.case, "final_score",      None),
            "confidence":       getattr(self.case, "final_confidence", None),
            # Challenge URL — empty string if not available
            "challenge_url":    self._challenge_url(),
        }

    def _challenge_url(self) -> str:
        try:
            api_base = self.config.get("api_base", None)
            if not api_base:
                parsed = urlparse(self.config.get("links", {}).get("submissions", ""))
                if parsed.scheme and parsed.netloc:
                    api_base = f"{parsed.scheme}://{parsed.netloc}"
            if not api_base:
                return ""
            token, _ = CaseChallengeToken.issue_token(self.case)
            return CaseChallengeToken.build_challenge_url(self.case.id, token, api_base)
        except Exception:
            return ""

    # ── send ───────────────────────────────────────────────────────────────

    def _send_action(self, user: str, subject: str) -> None:
        html = self.render_html(subject=subject)
        SendMailService.send_html(
            self.config.get("smtp", {}),
            sender=self.sender,
            recipient=user,
            subject=subject,
            html=html,
        )