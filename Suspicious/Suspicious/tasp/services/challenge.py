from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone

from dashboard.models import UserCasesMonthlyStats
from connectors.contrib.thehive.challenge import ChallengeToTheHiveService


def _load_mail_config() -> dict:
    from settings.config import get_section
    return get_section("email")


def _load_thehive_config() -> dict:
    from settings.config import get_section
    return get_section("integrations.thehive")


def get_submissions_url() -> str:
    return _load_mail_config().get("links", {}).get("submissions", "/submissions/")


class CaseChallengeService:
    def __init__(self, case, logger):
        self.case = case
        self.logger = logger

    def validate(self):
        if self.case.is_challenged or self.case.status == "Challenged":
            raise ValueError("Case already challenged")

    def mark_challenged(self, proposed: str = "", reason: str = ""):
        """Mark the case, keep the reporter's proposal and reason, and put the
        challenge on the case timeline, all or nothing. A second challenge of
        the same case (double submit, two tabs) is refused under the row lock."""
        from case_handler.lifecycle import LifecycleState, transition
        from case_handler.models import Case, CaseComment

        with transaction.atomic():
            fresh = Case.objects.select_for_update().get(pk=self.case.pk)
            if fresh.is_challenged or fresh.status == "Challenged":
                raise ValueError("Case already challenged")
            was = self.case.results
            self.case.is_challenged = True
            self.case.challenge_proposed_result = proposed
            self.case.challenge_reason = reason
            self.case.save(update_fields=["is_challenged", "challenge_proposed_result", "challenge_reason"])
            if self.case.lifecycle_state == LifecycleState.FINALIZED:
                transition(self.case, LifecycleState.CONTESTED)
            else:
                self.case.status = "Challenged"
                self.case.save(update_fields=["status"])
            body = f"Challenged the {was} verdict"
            body += f", proposing {proposed}" if proposed else ""
            CaseComment.objects.create(case=self.case, author=self.case.reporter,
                                       body=body + (f": {reason}" if reason else "."))

    def update_user_stats(self):
        _update_case_challenge_stats(self.case.reporter)

    def notify(self):
        send_to_thehive = _load_thehive_config().get("enabled", False)
        mail_header = f"Case ID {self.case.id} challenged by {self.case.reporter.username}"
        proposed = getattr(self.case, "challenge_proposed_result", "")
        if proposed:
            mail_header += f" (reporter says it should be {proposed})"
            reason = getattr(self.case, "challenge_reason", "")
            if reason:
                mail_header += f" (reason: {reason})"
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


def run_case_challenge(case, logger, proposed: str = "", reason: str = "") -> None:
    service = CaseChallengeService(case, logger)
    service.validate()
    service.mark_challenged(proposed, reason)
    service.update_user_stats()
    service.notify()


def notify_and_record_challenge(case, logger) -> None:
    """Stats + CERT/TheHive notification for an already-marked challenge.
    Unlike run_case_challenge, does NOT validate/mark: the caller (in-app
    view) has already marked the case, including the proposed verdict."""
    service = CaseChallengeService(case, logger)
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
