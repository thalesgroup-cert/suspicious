"""Elastic SIEM connector: forwards cases at or above a configurable verdict to
an operator-supplied Elasticsearch as ECS documents (one per case, _id = case
id, so retries and replays overwrite the same document).

See docs/specs/2026-10-14-elastic-siem-connector-design.md."""
from __future__ import annotations

import logging

from case_handler.models import Case
from connectors.base import (
    EVENT_CASE_FINALISED,
    EVENT_CASE_MODIFIED,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
)
from connectors.contrib.elastic_siem import service

logger = logging.getLogger("connectors.contrib.elastic_siem")


class ElasticSiemConnector(Connector):
    manifest = ConnectorManifest(
        name="elastic_siem",
        version="1.0.0",
        author="Thales CERT",
        category="SIEM",
        description=(
            "Forward finalised cases (verdict, score, mail subject/sender, IOCs) to Elasticsearch "
            "as ECS documents for Elastic Security. Verdict changes update the document. "
            "Run `manage.py reindex_siem` to backfill existing cases."
        ),
        config_schema=(
            ConfigField("url", "url", required=True,
                        help="Elasticsearch base URL, e.g. https://siem.internal:9200"),
            ConfigField("api_key", "secret", required=True,
                        help="Elasticsearch API key (the base64 'encoded' value)."),
            ConfigField("index", "str", default=service.DEFAULT_INDEX),
            ConfigField("min_verdict", "str", default=service.DEFAULT_MIN_VERDICT,
                        help="Lowest verdict forwarded: Safe, Inconclusive, Suspicious or Dangerous."),
            ConfigField("verify_tls", "bool", default=True),
            ConfigField("timeout_seconds", "int", default=service.DEFAULT_TIMEOUT),
            ConfigField("create_index", "bool", default=True,
                        help="Create the index with ECS mappings if it does not exist."),
            ConfigField("ui_base_url", "url", required=False,
                        help="Suspicious UI base URL; when set, documents carry a link to the case."),
        ),
        events=(EVENT_CASE_FINALISED, EVENT_CASE_MODIFIED),
        enabled_by_default=False,
    )

    def health_check(self) -> HealthStatus:
        try:
            service.min_rank(self.config)
            client = service.SiemClient(self.config)
        except ValueError as exc:
            return HealthStatus(ok=False, detail=str(exc))
        return client.health()

    def _forward(self, event, action: str) -> None:
        try:
            case = Case.objects.select_related(*service.CASE_RELATED).get(pk=event.case_id)
        except Case.DoesNotExist:
            return
        threshold = service.min_rank(self.config)  # validates min_verdict before any I/O
        rank = service.case_rank(case)
        if rank is None:
            return
        client = service.SiemClient(self.config)
        if rank >= threshold:
            client.ensure_index()
            client.put_case(case.pk, service.build_document(
                case, action, ui_base_url=self.config.get("ui_base_url") or "",
            ))
        elif action == EVENT_CASE_MODIFIED:
            # Downgraded below the threshold: fix the document only if it was ever sent.
            client.update_case(case.pk, service.build_update(case, action))

    def on_case_finalised(self, event) -> None:
        self._forward(event, EVENT_CASE_FINALISED)

    def on_case_modified(self, event) -> None:
        self._forward(event, EVENT_CASE_MODIFIED)
