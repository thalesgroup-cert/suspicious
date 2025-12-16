from typing import Dict, Optional, Any
from case_handler.case_utils.case_creator import CaseCreator
from mail_feeder.utils.user_creation.creation import UserCreationService
from .models import CaseInputData
from .utils import safe_execution
import logging

fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")
logger = logging.getLogger(__name__)


class CaseCreatorService:
    """
    Service for creating cases in a structured and safe way.
    """

    def __init__(self):
        self.create_user_service = UserCreationService()

    def create_case(self, data: CaseInputData) -> Optional[Any]:
        """
        Main entry point for creating a case.

        Args:
            data (dict): Dictionary containing required inputs.

        Returns:
            case instance if successfully created, else None
        """
        self._merge_ids(data)
        user_instance = self.create_user_service.get_or_create_user(data.user.username)

        case_dict = self._prepare_case_dict(data.instance)
        return self._execute_case_creation(case_dict, data.instance, user_instance)

    def _merge_ids(self, validated: CaseInputData) -> None:
        """
        Flatten and merge artifact_ids and attachment_ids into list_ids.
        """
        validated.list_ids.extend(validated.artifact_ids)
        validated.list_ids.extend(validated.attachment_ids)

    def _prepare_case_dict(self, mail_instance) -> Dict[str, Optional[Any]]:
        """
        Initialize the dictionary required by CaseCreator.create_case().
        """
        return {
            "file_instance": None,
            "ip_instance": None,
            "url_instance": None,
            "hash_instance": None,
            "mail_instance": mail_instance,
        }

    def _execute_case_creation(self, case_dict: Dict[str, Optional[Any]], mail_instance, user_instance) -> Optional[Any]:
        """
        Safely create and save a case.
        """
        case_creator = CaseCreator(user_instance)
        with safe_execution("creating case"):
            case = case_creator.create_case(**case_dict)
            fetch_mail_logger.debug(f"Created case: {getattr(case, 'id', 'None')}")
            if case and case.fileOrMail:
                fetch_mail_logger.debug(f"Linking mail to case: {getattr(case, 'id', 'None')}")
                case.fileOrMail.mail = mail_instance
                case.save()
            return case
