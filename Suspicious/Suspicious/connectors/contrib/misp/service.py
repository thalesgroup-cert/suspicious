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
from .internal import (
    allow_listed_domains,
    company_domains,
    is_allow_listed,
    is_company_domain,
    url_host,
)
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
        self._company_domains: frozenset = frozenset()
        self._allow_listed: frozenset = frozenset()

    # ── Case update ───────────────────────────────────────────────────────

    def update_misp(self, case: Case) -> None:
        self._company_domains = company_domains()
        self._allow_listed = allow_listed_domains()
        mem   = MISPEventManager(self.client)
        event = mem.get_or_create_event(case)
        if not event or not getattr(event, "id", None):
            raise RuntimeError("Could not get/create MISP event for case %s." % case.id)

        if case.results in SECONDARY_MISP_LEVELS:
            secondary_client = MISPClient(config=load_misp_settings().security)
            secondary_mem    = MISPEventManager(secondary_client)
        else:
            secondary_client = None
            secondary_mem    = None
        sec = {"secondary_mem": secondary_mem, "secondary_client": secondary_client}

        # One bad object must not stop the rest; failures are raised together so
        # the delivery is retried (pushes are deduplicated, so a retry is safe).
        errors: list[Exception] = []

        def push(fn, *args, **kwargs) -> None:
            try:
                fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                logger.error("MISP push failed for case %s: %s", case.id, exc, exc_info=True)
                errors.append(exc)

        if case.fileOrMail and getattr(case.fileOrMail, "mail", None):
            mail = Mail.objects.prefetch_related(*_UPDATE_MISP_PREFETCH).get(
                pk=case.fileOrMail.mail.pk
            )
            obj = build_email_object(mail, case.id, case.results, self._company_domains)
            if obj:
                push(self._push, event.id, obj, case.id, case.results, **sec)
            for attachment in mail.mail_attachments.all():
                push(self.add_attachment_object, event.id, attachment, case.id, case.results, **sec)
            for artifact in mail.mail_artifacts.all():
                push(self.add_artifact_object, event.id, artifact, case.id, case.results, **sec)

        if case.nonFileIocs:
            for ioc_type, ioc in case.nonFileIocs.get_iocs().items():
                if ioc:
                    push(self.add_artifact_object, event.id, ioc, case.id, case.results,
                         ioc_type=ioc_type, **sec)

        if errors:
            raise RuntimeError(
                "%d MISP push(es) failed for case %s: %s" % (len(errors), case.id, errors[0])
            ) from errors[0]

    def _push(self, event_id, obj, case_number, detection_level, *, secondary_mem, secondary_client) -> None:
        finalize_misp_object(self.client.misp, str(event_id), obj)
        self._maybe_push_monthly(obj, case_number, detection_level, secondary_mem, secondary_client)

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
        obj = self._build_artifact_object(artifact, case_number, detection_level, ioc_type)
        if obj:
            self._push(event_id, obj, case_number, detection_level,
                       secondary_mem=secondary_mem, secondary_client=secondary_client)

    def _build_artifact_object(
        self,
        artifact: Any,
        case_number: Any,
        detection_level: str,
        ioc_type: Optional[str],
    ) -> Optional[MISPObject]:
        if ioc_type:
            if ioc_type == "url" and isinstance(artifact, URL):
                if self._shareable_url(artifact):
                    return build_url_object(artifact, case_number, detection_level)
                return None
            if ioc_type == "domain" and isinstance(artifact, Domain):
                if self._shareable_domain(artifact):
                    return build_domain_object(artifact, case_number, detection_level)
                return None
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
            url = artifact.artifactIsUrl.url
            if not self._shareable_url(url):
                return None
            return build_url_object(url, case_number, detection_level)
        if artifact_type == "ip" and getattr(artifact, "artifactIsIp", None):
            return build_ip_object(artifact.artifactIsIp.ip, case_number, detection_level)
        if artifact_type == "hash" and getattr(artifact, "artifactIsHash", None):
            return build_hash_object(artifact.artifactIsHash.hash, case_number, detection_level)
        if artifact_type == "domain" and getattr(artifact, "artifactIsDomain", None):
            domain = artifact.artifactIsDomain.domain
            if not self._shareable_domain(domain):
                return None
            return build_domain_object(domain, case_number, detection_level)

        logger.warning(
            "[MISPHandler] Unsupported artifact_type %r for case %s — skipping.",
            artifact_type, case_number,
        )
        return None

    def _shareable_domain(self, domain: Domain) -> bool:
        """Allow-listed, legit and company domains (and their subdomains) are not indicators."""
        value = (domain.value or "").strip().lower()
        return (
            not is_company_domain(value, self._company_domains)
            and not is_allow_listed(value, self._allow_listed)
        )

    def _shareable_url(self, url: URL) -> bool:
        """A link on a company domain points at the victim, not at the attacker."""
        return not is_company_domain(url_host(url.address), self._company_domains)

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
        obj = build_hash_object(hash_obj, case_number, detection_level)
        if obj:
            self._push(event_id, obj, case_number, detection_level,
                       secondary_mem=secondary_mem, secondary_client=secondary_client)

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
        monthly_event = mem.get_or_create_monthly_event()
        if not monthly_event:
            raise RuntimeError("Could not get/create the monthly MISP event (case %s)." % case_number)

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
