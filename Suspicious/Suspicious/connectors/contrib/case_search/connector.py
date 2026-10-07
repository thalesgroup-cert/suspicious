"""Keeps the ``suspicious-cases`` Elasticsearch index current so the
investigations search box can query it instead of scanning SQL tables."""
from __future__ import annotations

from case_handler.models import Case
from connectors.base import (
    EVENT_CASE_CREATED,
    EVENT_CASE_FINALISED,
    EVENT_CASE_MODIFIED,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
)
from connectors.contrib.case_search import service


class CaseSearchConnector(Connector):
    manifest = ConnectorManifest(
        name="case_search",
        version="1.0.0",
        author="Thales CERT",
        category="Search",
        description="Index cases in Elasticsearch for fast investigation search. "
                    "Run `manage.py reindex_cases` before enabling.",
        config_schema=(
            ConfigField("url", "url", default=service.DEFAULT_URL, help="Elasticsearch URL"),
            ConfigField("index", "str", default=service.DEFAULT_INDEX, help="Index name"),
            ConfigField("timeout_seconds", "int", default=2, help="Search timeout"),
        ),
        events=(EVENT_CASE_CREATED, EVENT_CASE_MODIFIED, EVENT_CASE_FINALISED),
        enabled_by_default=False,
    )

    @property
    def index(self) -> str:
        return self.config.get("index") or service.DEFAULT_INDEX

    def health_check(self) -> HealthStatus:
        try:
            client = service.get_client(self.config, timeout=service.INDEX_TIMEOUT)
            status = client.cluster.health()["status"]
            return HealthStatus(ok=status in ("green", "yellow"), detail=f"cluster {status}")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=str(exc))

    def _index_case(self, event) -> None:
        try:
            case = Case.objects.select_related(*service.CASE_RELATED).get(pk=event.case_id)
        except Case.DoesNotExist:
            return
        client = service.get_client(self.config, timeout=service.INDEX_TIMEOUT)
        service.ensure_index(client, self.index)
        service.index_case(client, self.index, case)  # raises on failure: framework retries

    def on_case_created(self, event) -> None:
        self._index_case(event)

    def on_case_modified(self, event) -> None:
        self._index_case(event)

    def on_case_finalised(self, event) -> None:
        self._index_case(event)
