import logging
from datetime import date
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from .models import UsernameModel
from .utils import initialize_email_validator, create_ldap_user
from mail_feeder.utils.kpi_updating.kpis import (
    KpiService
)
from settings.models import WatcherLegitDomain


def _suspicious_email() -> str:
    from settings.config import get_section
    return get_section("branding").get("contact_email")


fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")


class UserCreationService:
    def __init__(self):
        COMPANY_DOMAINS = WatcherLegitDomain.objects.select_related('domain').values_list('domain__value', flat=True)
        self.email_validator = initialize_email_validator(COMPANY_DOMAINS)

    def get_or_create_user(self, username: str) -> User:
        validated = UsernameModel(username=username)
        today = date.today()
        month, year = today.strftime("%m"), today.year

        try:
            user = User.objects.get(username=validated.username)
            return user
        except ObjectDoesNotExist:
            return self._handle_user_creation(validated.username, month, year)
        except Exception as e:
            fetch_mail_logger.error(f"Error retrieving user {username}: {e}")
            return None

    def _handle_user_creation(self, username: str, month: str, year: int) -> User:
        validation_result = self.email_validator.is_company_email(username)
        if validation_result.is_valid:
            user = self.create_user(validation_result.normalized)
        else:
            fetch_mail_logger.warning("No User Found, defaulting to suspicious user...")
            user = self.create_default_user()

        KpiService.update_kpi_stats(month, year)
        KpiService.create_monthly_user_stats(user, month, year)
        create_ldap_user(user)

        return user

    def create_user(self, username: str) -> User:
        user, created = User.objects.get_or_create(username=username)
        if created:
            user.set_unusable_password()
            user.full_clean()
            user.save()
            fetch_mail_logger.info(f"User created: {username}")
        else:
            fetch_mail_logger.warning(f"User {username} already exists.")
        return user

    def create_default_user(self) -> User:
        suspicious_email = _suspicious_email()
        user, created = User.objects.get_or_create(username=suspicious_email)
        if created:
            user.set_unusable_password()
            user.save()
            fetch_mail_logger.info(f"Default suspicious user created: {suspicious_email}")
        return user
