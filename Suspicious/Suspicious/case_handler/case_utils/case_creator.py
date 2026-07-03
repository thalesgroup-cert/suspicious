from django.utils import timezone

from case_handler.models import (
    Case,
    CaseArtifact,
    CaseHasFileOrMail,
    CaseHasNonFileIocs,
)
import logging

from dashboard.models import UserCasesMonthlyStats
from django.db.models import F

fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")
logger = logging.getLogger(__name__)


class CaseCreator:
    def __init__(self, user):
        self.user = user

    def create_case(self, description=None, **kwargs):
        """
        Create a new case with the given parameters.

        Args:
            file_instance (File): The file associated with the case.
            ip_instance (IP): The IP address associated with the case.
            url_instance (URL): The URL associated with the case.
            hash_instance (Hash): The hash associated with the case.
            mail_instance (Mail): The email associated with the case.
            description (str): The description for the case.

        Returns:
            Case: The newly created case.
        """
        try:
            latest_case = Case.objects.latest('id')
            id_max = latest_case.id
        except Case.DoesNotExist:
            id_max = 0

        casestr = str(id_max + 1).zfill(6)

        case = Case(
            description=description or casestr,
            creation_date=timezone.now(),
            analysis_done=False,
            results="Suspicious",
            status="On Going",
            reporter=self.user
        )

        for key, value in kwargs.items():
            fetch_mail_logger.debug(f"Processing key: {key}, value: {getattr(value, 'id', 'None')}")
            if key == 'allow_listed' and value:
                case.results = "SAFE-ALLOW_LISTED"
                case.final_score = 0
                case.final_confidence = 100
                case.status = "Done"
                break

            if value:
                self._create_related_model(key, value, case)

        try:
            case.save()
            self._update_kpi_stats(case)
            self._update_user_cases_monthly_stats(case)
            case.save()
            return case
        except Exception as e:
            fetch_mail_logger.error(f"Error creating case: {e!s}")
            return None

    _ARTIFACT_KEY_MAP = {
        'file_instance': ('file', CaseArtifact.ArtifactType.FILE),
        'hash_instance': ('hash', CaseArtifact.ArtifactType.HASH),
        'url_instance': ('url', CaseArtifact.ArtifactType.URL),
        'ip_instance': ('ip', CaseArtifact.ArtifactType.IP),
        'mail_instance': ('mail', CaseArtifact.ArtifactType.MAIL),
    }

    def _create_related_model(self, key, value, case):
        """
        Records the (case, artifact) link in CaseArtifact, then attaches the
        artifact to the appropriate Case bundle (CaseHasFileOrMail for
        file/mail, CaseHasNonFileIocs for ip/url/hash).
        """
        case.save()

        mapping = self._ARTIFACT_KEY_MAP.get(key)
        if mapping is None:
            logger.warning("Unknown artifact key: %s", key)
            return
        fk_name, artifact_type = mapping

        try:
            CaseArtifact.objects.get_or_create(
                case=case,
                artifact_type=artifact_type,
                **{fk_name: value},
            )
        except Exception as e:
            logger.exception(
                "Error creating CaseArtifact for case=%s key=%s: %s",
                case.id, key, e,
            )
            return
        if key == 'file_instance' or key == 'mail_instance':
            try:
                case_file_or_mail = self._create_case_file_or_mail(key, value, case)
                if case_file_or_mail:
                    case_file_or_mail.save()
                    case.fileOrMail = case_file_or_mail
                    case.save()
            except Exception as e:
                print(f"Error creating case_file_or_mail: {e!s}")
        elif key == 'ip_instance' or key == 'url_instance' or key == 'hash_instance' and key != 'mail_instance' and key != 'file_instance':
            try:
                case_has_iocs = self._create_case_has_iocs(key, value, case)
                if case_has_iocs:
                    case_has_iocs.save()
                    case.nonFileIocs = case_has_iocs
                    case.save()
            except Exception as e:
                print(f"Error creating case_has_iocs: {e!s}")
        else:
            print("Done creating related model...")

    def _create_case_file_or_mail(self, key, value, case):
        """
        Create a CaseFileOrMail object based on the given key, value, and case.

        Args:
            key (str): The key indicating the type of IOC (mail_instance, file_instance, ip_instance, url_instance, hash_instance).
            value (object): The value representing the IOC instance.
            case (Case): The case object to associate the CaseFileOrMail object with.

        Returns:
            CaseFileOrMail: The created CaseFileOrMail object.
        """
        case_file_or_mail = None

        if key == 'mail_instance':
            case_file_or_mail = CaseHasFileOrMail(
                mail=value,
                case=case
            )
        elif key == 'file_instance':
            case_file_or_mail = CaseHasFileOrMail(
                file=value,
                case=case
            )

        return case_file_or_mail

    def _create_case_has_iocs(self, key, value, case):
        """
        Create a CaseHasIocs object based on the given key, value, and case.

        Args:
            key (str): The key indicating the type of IOC (mail_instance, file_instance, ip_instance, url_instance, hash_instance).
            value (object): The value representing the IOC instance.
            case (Case): The case object to associate the CaseHasIocs object with.

        Returns:
            CaseHasIocs: The created CaseHasIocs object.
        """
        case_has_iocs = None

        # Use a dictionary to map keys to attributes instead of multiple if-else statements
        file_or_mail_keys = {'mail_instance': 'mail', 'file_instance': 'file'}
        non_file_iocs_keys = {'ip_instance': 'ip', 'url_instance': 'url', 'hash_instance': 'hash'}

        if key in file_or_mail_keys:
            case_has_iocs = CaseHasFileOrMail(
                **{file_or_mail_keys[key]: value, 'case': case}
            )
        elif key in non_file_iocs_keys:
            case_has_iocs = CaseHasNonFileIocs(
                **{non_file_iocs_keys[key]: value, 'case': case}
            )

        # Add error handling for invalid keys
        else:
            raise ValueError(f"Invalid key: {key}. Expected one of {list(file_or_mail_keys.keys()) + list(non_file_iocs_keys.keys())}")

        return case_has_iocs

    def _update_kpi_stats(self, case):
        """
        Update the KPI statistics based on the given case.

        Args:
            case: The case object to update the statistics for.

        Returns:
            None
        """
        try:
            from tasp.cron.kpi import sync_monthly_kpi
            kpi = sync_monthly_kpi()

            # Only update the stats if the case results are "SAFE-ALLOW_LISTED"
            if case.results == "SAFE-ALLOW_LISTED":
                if kpi.monthly_cases_summary:
                    kpi.monthly_cases_summary.allow_listed_cases += 1
                    kpi.monthly_cases_summary.save()
                else:
                    print("No MonthlyCasesSummary associated with KPI")

        except Exception as e:
            print(f"Error updating KPI stats: {e!s}")

    def _update_user_cases_monthly_stats(self, case):
        """
        Updates the monthly statistics for the user's cases.

        Args:
            case: The case object to update the statistics for.

        Returns:
            None
        """
        try:
            from tasp.cron.kpi import sync_monthly_kpi
            kpi = sync_monthly_kpi()

            user_cases_monthly_stats = UserCasesMonthlyStats.objects.filter(user=self.user, month=kpi.month, year=kpi.year).first()
            if not user_cases_monthly_stats:
                user_cases_monthly_stats = UserCasesMonthlyStats(user=self.user, month=kpi.month, year=kpi.year)

            # Only update the stats if the case results are "SAFE-ALLOW_LISTED"
            if case.results == "SAFE-ALLOW_LISTED":
                user_cases_monthly_stats.allow_listed_cases = F('allow_listed_cases') + 1
                user_cases_monthly_stats.save(update_fields=['allow_listed_cases'])

        except Exception as e:
            print(f"Error updating user cases monthly stats: {e!s}")

    def _get_related_model(self, key):
        """
        Deprecated. Kept for backwards compatibility — returns CaseArtifact
        for any known key. Prefer the consolidated write path in
        _create_related_model.
        """
        if key not in self._ARTIFACT_KEY_MAP:
            raise ValueError(
                f"Invalid key: {key}. Valid keys are "
                f"{', '.join(self._ARTIFACT_KEY_MAP.keys())}"
            )
        return CaseArtifact

    def _get_related_field(self, key):
        """
        Get the related field name based on the given key.

        Args:
            key (str): The key for which to retrieve the related field name.

        Returns:
            str: The related field name corresponding to the given key.
        """
        related_fields = {
            'file_instance': 'fileOrMail',
            'ip_instance': 'nonFileIocs',
            'url_instance': 'nonFileIocs',
            'hash_instance': 'nonFileIocs',
            'mail_instance': 'fileOrMail'
        }

        if key not in related_fields:
            raise ValueError(f"Invalid key: {key}. Valid keys are {', '.join(related_fields.keys())}.")

        return related_fields.get(key)
