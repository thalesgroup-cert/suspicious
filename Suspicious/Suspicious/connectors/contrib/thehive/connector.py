"""TheHive connector — config/health home for the challenge + campaign flows.

The challenge flow (tasp/services/challenge.py) and AI phishing-campaign
detection import this package's modules directly. On top of that, the
``case_finalised`` hook pushes IOC-group cases (Case.observable_group) as a
single alert carrying every observable — mail/file/challenge cases are left to
the direct-import paths. The connector gives all of this a single config
section, a health probe, and a Settings UI card."""
from __future__ import annotations

from common.http_client import make_session
from connectors.base import (
    EVENT_CASE_FINALISED,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
)


class TheHiveConnector(Connector):
    manifest = ConnectorManifest(
        name="thehive",
        version="1.0.0",
        author="Thales CERT",
        category="Incident Response",
        description="TheHive alerts for challenged cases and phishing campaigns.",
        config_schema=(
            ConfigField("url", "url", required=True),
            ConfigField("api_key", "secret", required=True),
            ConfigField("certificate_path", "str",
                        help="CA bundle path; empty = system trust store"),
        ),
        events=(EVENT_CASE_FINALISED,),
    )

    def on_case_finalised(self, event) -> None:
        from case_handler.models import Case
        from connectors.contrib.thehive.phishing import (
            THEHIVE_SEVERITY,
            add_observables_to_item,
            build_group_observables,
            create_new_alert,
        )

        case = Case.objects.get(pk=event.case_id)
        if not case.observable_group_id:
            return  # isolation — mail/file cases keep the challenge-flow path

        url, key = self.config.get("url"), self.config.get("api_key")
        if not url or not key:
            return

        observables = build_group_observables(case)
        if not observables:
            return

        severity = THEHIVE_SEVERITY.get(str(case.results), 2)

        alert = create_new_alert(
            None,
            f"Suspicious IOC case #{case.id}",
            f"{len(observables)} indicator(s) — verdict {case.results}",
            severity, 2, 2, "Suspicious", url, key,
            [f"suspicious:case:{case.id}"],
        )
        alert_id = (alert or {}).get("_id")
        if alert_id:
            add_observables_to_item("alert", alert_id, observables, url, key)
            # record it so a later manual "Push to TheHive" updates this alert
            # instead of creating a duplicate.
            if not case.thehive_alert_id:
                case.thehive_alert_id = alert_id
                case.save(update_fields=["thehive_alert_id"])

    def health_check(self) -> HealthStatus:
        url, key = self.config.get("url"), self.config.get("api_key")
        if not url or not key:
            return HealthStatus(ok=False, detail="url/api_key not configured")
        try:
            response = make_session().get(
                f"{url.rstrip('/')}/api/v1/user/current",
                headers={"Authorization": f"Bearer {key}"},
                timeout=10,
                verify=self.config.get("certificate_path") or True,
            )
            response.raise_for_status()
            return HealthStatus(ok=True, detail="authenticated")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=str(exc))
