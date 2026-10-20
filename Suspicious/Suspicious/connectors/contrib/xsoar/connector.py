"""Cortex XSOAR connector: opens one XSOAR incident for each finalised case at or
above a configurable verdict, carrying the verdict, the rationale and the
per-observable verdicts. Cases an XSOAR playbook submitted itself are skipped:
the incident they came from already exists.

See docs/specs/2026-10-20-xsoar-connector-design.md."""
from __future__ import annotations

import logging

from django.db import transaction

from case_handler.models import Case
from connectors.base import (
    EVENT_CASE_FINALISED,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
)
from connectors.contrib.xsoar import service
from connectors.models import ConnectorLink

logger = logging.getLogger("connectors.contrib.xsoar")

NAME = "xsoar"


class XsoarConnector(Connector):
    manifest = ConnectorManifest(
        name=NAME,
        version="1.0.0",
        author="Thales CERT",
        category="SOAR",
        description=(
            "Open a Cortex XSOAR incident for each finalised case at or above min_verdict, with the "
            "verdict, rationale and per-observable verdicts. One incident per case; cases submitted "
            "by an XSOAR playbook are skipped."
        ),
        config_schema=(
            ConfigField("url", "url", required=True,
                        help="XSOAR API base URL: https://xsoar.internal (XSOAR 6) or "
                             "https://api-<tenant>.xdr.<region>.paloaltonetworks.com (XSOAR 8)."),
            ConfigField("api_key", "secret", required=True,
                        help="XSOAR API key. It needs permission to create incidents."),
            ConfigField("api_key_id", "str",
                        help="XSOAR 8 only: the API key ID (sent as x-xdr-auth-id). Leave empty for XSOAR 6."),
            ConfigField("incident_type", "str",
                        help="XSOAR incident type for the new incidents, for example Phishing. "
                             "Empty lets XSOAR apply its default."),
            ConfigField("min_verdict", "str", default=service.DEFAULT_MIN_VERDICT,
                        help="Lowest verdict pushed: Safe, Inconclusive, Suspicious or Dangerous."),
            ConfigField("create_investigation", "bool", default=True,
                        help="Open the investigation so the incident type's playbook runs."),
            ConfigField("skip_ref_prefix", "str", default=service.DEFAULT_SKIP_PREFIX,
                        help="Cases whose external_ref starts with this were submitted by XSOAR and "
                             "are not pushed back. Empty turns the check off."),
            ConfigField("verify_tls", "bool", default=True),
            ConfigField("timeout_seconds", "int", default=service.DEFAULT_TIMEOUT),
            ConfigField("ui_base_url", "url", required=False,
                        help="Suspicious UI base URL; when set, incidents carry a link to the case."),
        ),
        events=(EVENT_CASE_FINALISED,),
        enabled_by_default=False,
    )

    def health_check(self) -> HealthStatus:
        try:
            service.min_rank(self.config)
            client = service.XsoarClient(self.config)
        except ValueError as exc:
            return HealthStatus(ok=False, detail=str(exc))
        return client.health()

    def on_case_finalised(self, event) -> None:
        try:
            case = Case.objects.select_related("fileOrMail__mail").get(pk=event.case_id)
        except Case.DoesNotExist:
            return

        threshold = service.min_rank(self.config)  # validates min_verdict before any I/O
        rank = service.case_rank(case)
        if rank is None or rank < threshold:
            return
        if service.originated_in_xsoar(case, self.config):
            logger.info("case %s came from XSOAR (external_ref %r); not pushed back", case.pk, case.external_ref)
            return

        client = service.XsoarClient(self.config)

        from api.views.submissions import build_ticket  # lazy: api imports connectors

        body = service.build_incident(
            case, build_ticket(case),
            incident_type=(self.config.get("incident_type") or "").strip(),
            create_investigation=service.as_bool(self.config.get("create_investigation"), True),
            ui_base_url=self.config.get("ui_base_url") or "",
        )

        # The unique row makes a second delivery for the same case wait for the
        # first, then see the incident id and stop. A failed push rolls the row
        # back, so the framework's retry creates the incident.
        with transaction.atomic():
            link, _ = ConnectorLink.objects.select_for_update().get_or_create(
                connector=NAME, case_id=case.pk,
            )
            if link.remote_id:
                return
            # "created" when XSOAR answered 2xx without an id: still recorded, so a
            # retry or a replay cannot open a second incident.
            link.remote_id = client.create_incident(body) or "created"
            link.save(update_fields=["remote_id", "updated_at"])
        logger.info("case %s pushed to XSOAR as incident %s", case.pk, link.remote_id)
