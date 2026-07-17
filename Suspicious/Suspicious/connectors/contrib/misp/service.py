"""
MISP service — orchestrates case and artifact pushing.
"""
from __future__ import annotations
import logging
from typing import Any, Optional

from pymisp import MISPObject

from case_handler.models import Case
from ip_process.models import IP
from url_process.models import URL
from hash_process.models import Hash
from domain_process.models import Domain
from mail_feeder.models import Mail

from .client import MISPClient
from .config_loader import load_misp_settings
from .events import MISPEventManager
from .objects import (
    build_domain_object,
    build_email_object,
    build_hash_object,
    build_ip_object,
    build_url_object,
    finalize_misp_object,
)
from .utils import SECONDARY_MISP_LEVELS

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


_UPDATE_MISP_PREFETCH = (
    "mail_artifacts__artifactIsIp__ip",
    "mail_artifacts__artifactIsUrl__url",
    "mail_artifacts__artifactIsHash__hash",
    "mail_artifacts__artifactIsDomain__domain",
)


class MISPService:
    def __init__(self, primary: bool = True) -> None:
        settings     = load_misp_settings()
        config       = settings.suspicious if primary else settings.security
        self.client  = MISPClient(config=config)
        self.primary = primary

    # ── Case update ───────────────────────────────────────────────────────

    def update_misp(self, case: Case) -> None:
        try:
            mem   = MISPEventManager(self.client)
            event = mem.get_or_create_event(case)
            if not event or not getattr(event, "id", None):
                logger.error("Could not get/create MISP event for case %s.", case.id)
                return

            if case.results in SECONDARY_MISP_LEVELS:
                secondary_client = MISPClient(config=load_misp_settings().security)
                secondary_mem    = MISPEventManager(secondary_client)
            else:
                secondary_client = None
                secondary_mem    = None

            if case.fileOrMail and getattr(case.fileOrMail, "mail", None):
                mail = Mail.objects.prefetch_related(*_UPDATE_MISP_PREFETCH).get(
                    pk=case.fileOrMail.mail.pk
                )
                obj  = build_email_object(mail, case.id, case.results)
                if obj:
                    finalize_misp_object(self.client.misp, event.id, obj)
                    self._maybe_push_monthly(
                        obj, case.id, case.results, secondary_mem, secondary_client
                    )

                if getattr(mail, "mail_attachments", None):
                    for attachment in mail.mail_attachments.all():
                        self.add_attachment_object(
                            event.id, attachment, case.id, case.results,
                            secondary_mem=secondary_mem,
                            secondary_client=secondary_client,
                        )

                if getattr(mail, "mail_artifacts", None):
                    for artifact in mail.mail_artifacts.all():
                        self.add_artifact_object(
                            event.id, artifact, case.id, case.results,
                            secondary_mem=secondary_mem,
                            secondary_client=secondary_client,
                        )

            if getattr(case, "nonFileIocs", None) and case.nonFileIocs:
                for ioc_type, ioc in case.nonFileIocs.get_iocs().items():
                    if ioc:
                        self.add_artifact_object(
                            event.id, ioc, case.id, case.results,
                            ioc_type=ioc_type,
                            secondary_mem=secondary_mem,
                            secondary_client=secondary_client,
                        )

        except Exception as exc:
            logger.error("Error updating MISP for case %s: %s", case.id, exc, exc_info=True)
            raise

    # ── Artifact routing ──────────────────────────────────────────────────

    def add_artifact_object(
        self,
        event_id: str,
        artifact: Any,
        case_number: Any,
        detection_level: str,
        ioc_type: Optional[str] = None,
        *,
        secondary_mem:    Optional[MISPEventManager] = None,
        secondary_client: Optional[MISPClient]       = None,
    ) -> None:
        try:
            obj = self._build_artifact_object(artifact, case_number, detection_level, ioc_type)
            if not obj:
                return
            finalize_misp_object(self.client.misp, event_id, obj)
            self._maybe_push_monthly(
                obj, case_number, detection_level, secondary_mem, secondary_client
            )
        except Exception as exc:
            logger.error(
                "[MISPHandler] Error adding artifact to event %s: %s",
                event_id, exc, exc_info=True,
            )

    def _build_artifact_object(
        self,
        artifact: Any,
        case_number: Any,
        detection_level: str,
        ioc_type: Optional[str],
    ) -> Optional[MISPObject]:
        if ioc_type:
            if ioc_type == "url" and isinstance(artifact, URL):
                return build_url_object(artifact, case_number, detection_level)
            if ioc_type == "domain" and isinstance(artifact, Domain):
                return build_domain_object(artifact, case_number, detection_level)
            if ioc_type == "ip" and isinstance(artifact, IP):
                return build_ip_object(artifact, case_number, detection_level)
            if ioc_type == "hash" and isinstance(artifact, Hash):
                return build_hash_object(artifact, case_number, detection_level)
            logger.warning(
                "[MISPHandler] Unsupported ioc_type %r for case %s — skipping.",
                ioc_type, case_number,
            )
            return None

        artifact_type = (getattr(artifact, "artifact_type", None) or "").lower()
        if artifact_type == "url" and getattr(artifact, "artifactIsUrl", None):
            return build_url_object(artifact.artifactIsUrl.url, case_number, detection_level)
        if artifact_type == "ip" and getattr(artifact, "artifactIsIp", None):
            return build_ip_object(artifact.artifactIsIp.ip, case_number, detection_level)
        if artifact_type == "hash" and getattr(artifact, "artifactIsHash", None):
            return build_hash_object(artifact.artifactIsHash.hash, case_number, detection_level)
        if artifact_type == "domain" and getattr(artifact, "artifactIsDomain", None):
            return build_domain_object(artifact.artifactIsDomain.domain, case_number, detection_level)

        logger.warning(
            "[MISPHandler] Unsupported artifact_type %r for case %s — skipping.",
            artifact_type, case_number,
        )
        return None

    def add_attachment_object(
        self,
        event_id: str,
        attachment: Any,
        case_number: Any,
        detection_level: str,
        *,
        secondary_mem:    Optional[MISPEventManager] = None,
        secondary_client: Optional[MISPClient]       = None,
    ) -> None:
        file_obj = getattr(attachment, "file", None)
        hash_obj = getattr(file_obj, "linked_hash", None)
        if hash_obj is None:
            logger.warning(
                "[MISPHandler] Attachment %s on case %s has no linked hash — skipping.",
                getattr(attachment, "id", attachment), case_number,
            )
            return
        try:
            obj = build_hash_object(hash_obj, case_number, detection_level)
            if not obj:
                return
            finalize_misp_object(self.client.misp, event_id, obj)
            self._maybe_push_monthly(
                obj, case_number, detection_level, secondary_mem, secondary_client
            )
        except Exception as exc:
            logger.error(
                "[MISPHandler] Error adding attachment to event %s: %s",
                event_id, exc, exc_info=True,
            )

    # ── Monthly event push ────────────────────────────────────────────────

    def _maybe_push_monthly(
        self,
        misp_object:     MISPObject,
        case_number:     Any,
        detection_level: str,
        mem:             Optional[MISPEventManager],
        client:          Optional[MISPClient],
    ) -> None:
        """Push a copy of misp_object to the secondary monthly event when warranted."""
        if detection_level not in SECONDARY_MISP_LEVELS or not mem or not client:
            return
        try:
            monthly_event = mem.get_or_create_monthly_event()
            if not monthly_event:
                return

            monthly_id = getattr(monthly_event, "id", None)
            if not monthly_id:
                logger.warning(
                    "Monthly MISP event has no id for case %s.", case_number
                )
                return

            new_obj = MISPObject(misp_object.name)
            for attr in misp_object.attributes:
                if attr.object_relation and attr.value:
                    attr_type = getattr(attr, "type", None) or attr.object_relation
                    new_obj.add_attribute(
                        attr.object_relation, type=attr_type, value=attr.value
                    )

            finalize_misp_object(client.misp, str(monthly_id), new_obj)

        except Exception as exc:
            logger.error(
                "Error pushing to monthly MISP event for case %s: %s",
                case_number, exc, exc_info=True,
            )