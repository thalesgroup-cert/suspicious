from email_validator import validate_email, EmailNotValidError

from .models import EmailValidationResult, ConfigModel

class EmailValidatorService:
    def __init__(self, config: ConfigModel):
        # Normalize to lowercase domains internally
        self.company_domains = {d.strip().lower() for d in config.company_domains}

    def validate_email_syntax(self, email: str) -> EmailValidationResult:
        """
        Validate the email syntax (and optionally deliverability).
        Returns an EmailValidationResult with normalized form or error.
        """
        try:
            v = validate_email(email, check_deliverability=False)
            return EmailValidationResult(is_valid=True, normalized=v.email)
        except EmailNotValidError as e:
            return EmailValidationResult(is_valid=False, error=str(e))

    def is_company_email(self, email: str) -> EmailValidationResult:
        """
        Validate email syntax and ensure its domain belongs to configured company domains.
        """
        # First validate syntax
        result = self.validate_email_syntax(email)
        if not result.is_valid:
            return result

        # At this point result.normalized is non-None
        normalized = result.normalized  # type: ignore
        domain = normalized.split("@")[1].lower()
        if domain in self.company_domains:
            return EmailValidationResult(is_valid=True, normalized=normalized)
        else:
            return EmailValidationResult(
                is_valid=False,
                normalized=normalized,
                error=f"Domain '{domain}' is not among allowed: {sorted(self.company_domains)}"
            )
