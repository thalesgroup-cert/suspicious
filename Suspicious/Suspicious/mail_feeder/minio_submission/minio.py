import os
import logging
from typing import Optional
from django.contrib.auth import get_user_model
from django.db.models import Q
from settings.models import WatcherLegitDomain

from mail_feeder.global_submission.gsubmission import GlobalSubmissionService as glo
from mail_feeder.global_submission.models import MailSubmissionData
from mail_feeder.utils.user_creation.creation import UserCreationService

from .utils import safe_execution

fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")
logger = logging.getLogger(__name__)

User = get_user_model()


# ---------------------------------------------------------------------------
# User resolution
# ---------------------------------------------------------------------------

def _get_user_by_email(email: str) -> Optional[object]:
    """
    Look up a Django user whose email matches `email` (case-insensitive).

    This is the fast path used when reported_by comes from metadata.json —
    the full address is already known, no variant generation required.
    """
    if not email or "@" not in email:
        return None
    return User.objects.filter(email__iexact=email).first()


def _get_user_by_username_variants(username: str) -> Optional[object]:
    """
    Fallback: look up a user by trying common username formats against all
    legitimate domains stored in WatcherLegitDomain.

    Used only when reported_by was not available from the manifest and we
    fall back to parsing the username out of the workdir path.

    Variants tried for 'first.last':
        first.last, f.last, first_last, first-last
    """
    try:
        first, last = username.split(".", 1)
        variants = {
            username,
            f"{first[0]}.{last}",
            f"{first}_{last}",
            f"{first}-{last}",
        }
    except ValueError:
        variants = {username}

    legit_domains = (
        WatcherLegitDomain.objects
        .select_related("domain")
        .values_list("domain__value", flat=True)
    )

    query = Q()
    for variant in variants:
        for domain in legit_domains:
            query |= Q(email__iexact=f"{variant}@{domain}")

    return User.objects.filter(query).first()


def _resolve_user(
    reported_by: str,
    workdir: str,
) -> Optional[object]:
    """
    Resolve the reporting user from best-available source.

    Priority:
      1. reported_by (full email from metadata.json) — direct DB lookup,
         no guessing.
      2. reported_by, via the same get-or-create-and-LDAP-enrich flow the
         case_creator path already uses — covers a legitimate reporter who
         has no Django User yet (e.g. LDAP sync hasn't run for them).
      3. Username extracted from the workdir path convention
         (e.g. 'theo.bhang-submission-260326141159/...') — tried against
         all legitimate domains via variant generation.
      4. None — processing continues with an empty user field.

    The path-convention fallback exists only for buckets that predate
    metadata.json. Remove it once all feeder-produced buckets write manifests.
    """
    if reported_by:
        user = _get_user_by_email(reported_by)
        if user:
            fetch_mail_logger.info(
                "Resolved user %s from reported_by=%s", user.email, reported_by
            )
            return user
        fetch_mail_logger.warning(
            "No user found for reported_by=%s — trying LDAP-backed creation",
            reported_by,
        )
        user = UserCreationService().get_or_create_user(reported_by)
        if user:
            fetch_mail_logger.info(
                "Created/resolved user %s from reported_by=%s via LDAP",
                user.username, reported_by,
            )
            return user
        fetch_mail_logger.warning(
            "LDAP-backed creation failed for reported_by=%s — falling back to path parsing",
            reported_by,
        )

    username: Optional[str] = None
    for part in workdir.split(os.sep):
        if "-submission-" in part:
            username = part.split("-submission-")[0]
            break

    if not username:
        fetch_mail_logger.warning(
            "Could not extract username from workdir %s and no reported_by provided",
            workdir,
        )
        return None

    user = _get_user_by_username_variants(username)
    if user:
        fetch_mail_logger.info(
            "Resolved user %s from path username %s", user.email, username
        )
    else:
        fetch_mail_logger.warning(
            "No user found for path username %s", username
        )
    return user


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class MinioEmailService:
    """
    Service for processing emails from MinIO work directories.
    """

    def __init__(self, email_handler=None):
        self.email_handler = email_handler

    def process_emails_from_minio_workdir(
        self,
        workdir: str,
        bucket_name: str,
        reported_by: str = "",
        reporter_note: str = "",
    ) -> None:
        """
        Process all regular .eml files in a given MinIO work directory.

        Args:
            workdir:      Local filesystem path to the downloaded email directory.
            bucket_name:  Source MinIO bucket name.
            reported_by:  Reporter's email address as extracted from metadata.json.
                          When provided, user resolution is a direct DB lookup
                          instead of path-convention parsing + variant generation.
                          Defaults to "" for backward compatibility with callers
                          that do not yet pass the manifest value.
        """
        email_id = os.path.basename(workdir)

        with safe_execution(f"processing MinIO emails {email_id}"):
            fetch_mail_logger.info("Processing MinIO emails in %s", workdir)

            user = _resolve_user(reported_by=reported_by, workdir=workdir)

            eml_files = glo().list_eml_files(workdir=workdir, prefix="user_submission")

            for filename in eml_files:
                fetch_mail_logger.debug("Processing MinIO email file %s", filename)

                try:
                    glo().process_single_email(
                        MailSubmissionData(
                            workdir=workdir,
                            filename=filename,
                            email_id=email_id,
                            user=user.email if user else "",
                            bucket_name=bucket_name,
                            is_submitted=False,
                            reported_by=reported_by,
                            reporter_note=reporter_note,
                        )
                    )
                except Exception:
                    fetch_mail_logger.exception(
                        "Failed to process email %s in %s; skipping", filename, workdir
                    )
                    continue