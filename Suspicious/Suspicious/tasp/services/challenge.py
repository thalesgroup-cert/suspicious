import json
import os
from functools import lru_cache

from django.contrib.auth.models import User
from django.utils import timezone

from dashboard.models import UserCasesMonthlyStats
from score_process.score_utils.thehive.challenge import ChallengeToTheHiveService


CONFIG_PATH = os.environ.get("SUSPICIOUS_SETTINGS_PATH", "/app/settings.json")


@lru_cache(maxsize=1)
def _load_mail_config() -> dict:
    with open(CONFIG_PATH) as config_file:
        return json.load(config_file).get("mail", {})


@lru_cache(maxsize=1)
def _load_thehive_config() -> dict:
    with open(CONFIG_PATH) as config_file:
        return json.load(config_file).get("thehive", {})


def get_submissions_url() -> str:
    return _load_mail_config().get("submissions", "/submissions/")


class CaseChallengeService:
    def __init__(self, case, logger):
        self.case = case
        self.logger = logger

    def validate(self):
        if self.case.is_challenged or self.case.status == "Challenged":
            raise ValueError("Case already challenged")

    def mark_challenged(self):
        self.case.is_challenged = True
        self.case.status = "Challenged"
        self.case.save(update_fields=["is_challenged", "status"])

    def update_user_stats(self):
        _update_case_challenge_stats(self.case.reporter)

    def notify(self):
        send_to_thehive = _load_thehive_config().get("enabled", False)
        mail_header = f"Case ID {self.case.id} challenged by {self.case.reporter.username}"
        self.logger.info(
            "Notifying about challenge for case ID %s. Send to TheHive: %s",
            self.case.id,
            send_to_thehive,
        )
        if send_to_thehive:
            self.logger.info("Sending challenge notification to TheHive for case ID %s", self.case.id)
            ChallengeToTheHiveService(self.case, None, mail_header).send_to_thehive()
            self.logger.info("Challenge notification sent to TheHive for case ID %s", self.case.id)
        else:
            cert_users = User.objects.filter(groups__name="CERT", is_active=True).exclude(email="")
            for cert_user in cert_users:
                ChallengeToTheHiveService(self.case, cert_user, mail_header).send()


def run_case_challenge(case, logger) -> None:
    service = CaseChallengeService(case, logger)
    service.validate()
    service.mark_challenged()
    service.update_user_stats()
    service.notify()


def _update_case_challenge_stats(user):
    now = timezone.now()
    stats, _ = UserCasesMonthlyStats.objects.get_or_create(
        user=user,
        month=now.strftime("%m"),
        year=now.year,
        defaults={"challenged_cases": 0, "total_cases": 0},
    )
    stats.challenged_cases += 1
    stats.save()
