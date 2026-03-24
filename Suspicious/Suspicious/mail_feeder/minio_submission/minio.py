import os
import logging
from typing import Optional
import json
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q

from mail_feeder.global_submission.gsubmission import GlobalSubmissionService as glo
from mail_feeder.global_submission.models import MailSubmissionData

from .utils import safe_execution
CONFIG_PATH = "/app/settings.json"
fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")
logger = logging.getLogger(__name__)

User = get_user_model()

with open(CONFIG_PATH) as f:
    conf = json.load(f)

COMPANY_DOMAINS=conf.get("company_domains", {})


def extract_username_from_path(path: str) -> Optional[str]:
    for part in path.split(os.sep):
        if "-submission-" in part:
            return part.split("-submission-")[0]
    return None


def generate_user_variants(username: str) -> set[str]:
    try:
        first, last = username.split(".")
    except ValueError:
        return {username}

    return {
        username,
        f"{first[0]}.{last}",
        f"{first}_{last}",
        f"{first}-{last}",
    }


def get_user_from_username(username: str):
    variants = generate_user_variants(username)

    query = Q()
    for variant in variants:
        for domain in COMPANY_DOMAINS:
            query |= Q(email__iexact=f"{variant}@{domain}")

    return User.objects.filter(query).first()


class MinioEmailService:
    """
    Service for processing emails from MinIO work directories.
    """

    def __init__(self, email_handler=None):
        self.email_handler = email_handler

    def process_emails_from_minio_workdir(self, workdir: str, bucket_name: str) -> None:
        """
        Process all regular emails in a given MinIO work directory.
        """
        email_id = os.path.basename(workdir)

        with safe_execution(f"processing MinIO emails {email_id}"):
            fetch_mail_logger.info(f"Processing MinIO emails in {workdir}")

            # Resolve user from workdir
            username = extract_username_from_path(workdir)
            user = None

            if username:
                user = get_user_from_username(username)
                if user:
                    fetch_mail_logger.info(f"Resolved user {user.email} from username {username}")
                else:
                    fetch_mail_logger.warning(f"No user found for username {username}")
            else:
                fetch_mail_logger.warning(f"Could not extract username from workdir {workdir}")

            eml_files = glo().list_eml_files(workdir=workdir, prefix="user_submission")

            for filename in eml_files:
                fetch_mail_logger.debug(f"Processing MinIO email file {filename}")

                glo().process_single_email(
                    MailSubmissionData(
                        workdir=workdir,
                        filename=filename,
                        email_id=email_id,
                        user=user.email if user else "",
                        bucket_name=bucket_name,
                        is_submitted=False
                    )
                )