import json
import logging
from typing import Iterable, Tuple, Optional

import json
from thehive4py import TheHiveApi

from .models import (
    AlertCreate,
    Observable,
    Comment,
    TheHiveConfig,
)
from .utils import generate_ref


logger = logging.getLogger(__name__)
update_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

CONFIG_PATH = "/app/settings.json"


class TheHiveService:
    """
    Thin service layer over TheHive 5 API (thehive4py).
    No business logic.
    """

    def __init__(self, config: TheHiveConfig):
        self.config = config
        self.api = TheHiveApi(
            url=config.url,
            apikey=config.api_key,
            verify=config.certificate_path,
        )

    # ---------- factory ----------

    @classmethod
    def from_settings(cls, path: str = CONFIG_PATH) -> "TheHiveService":
        with open(path) as f:
            raw = json.load(f).get("thehive", {})
        return cls(TheHiveConfig(**raw))

    # ---------- alerts ----------

    def create_alert(self, alert: AlertCreate) -> Optional[dict]:
        source_ref = alert.source_ref or generate_ref()

        payload = {
            "type": alert.app_name,
            "source": "suspicious",
            "sourceRef": source_ref,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "tlp": alert.tlp,
            "pap": alert.pap,
            "tags": alert.tags,
            "customFields": {"tha-id": source_ref},
        }

        try:
            return self.api.alert.create(alert=payload)
        except Exception as e:
            update_logger.info(f"Alert creation failed: {e}")
            return None

    # ---------- generic retrieval ----------

    def get_item(self, item_id: str) -> Tuple[Optional[str], Optional[dict]]:
        try:
            case = self.api.case.get(item_id)
            if case:
                return "case", case
        except Exception:
            pass

        try:
            alert = self.api.alert.get(item_id)
            if alert:
                return "alert", alert
        except Exception:
            pass

        return None, None

    # ---------- observables ----------

    def add_observables(
        self,
        item_type: str,
        item_id: str,
        observables: Iterable[Observable],
    ) -> None:
        for obs in observables:
            try:
                self.api.observable.create(
                    observable={
                        **obs.model_dump(),
                        "tlp": obs.tlp,
                        "pap": obs.pap,
                    },
                    case_id=item_id if item_type == "case" else None,
                    alert_id=item_id if item_type == "alert" else None,
                )
            except Exception as e:
                update_logger.info(
                    f"Observable add failed ({obs.data}): {e}"
                )

    # ---------- attachments ----------

    def add_attachments(
        self,
        item_type: str,
        item_id: str,
        paths: Iterable[str],
    ) -> None:
        for path in paths:
            try:
                self.api.alert.add_attachment(
                    alert_id=item_id,
                    file_path=path,
                )
            except Exception as e:
                update_logger.info(
                    f"Attachment failed ({path}): {e}"
                )

    # ---------- comments ----------

    def add_comment(
        self,
        item_type: str,
        item_id: str,
        comment: Comment,
    ) -> None:
        try:
            self.api.comment.create(
                comment=comment.model_dump(),
                case_id=item_id if item_type == "case" else None,
                alert_id=item_id if item_type == "alert" else None,
            )
        except Exception as e:
            update_logger.info(f"Comment add failed: {e}")


