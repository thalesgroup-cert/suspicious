"""TheHive connector: config and health for the challenge flow, plus campaign alerts.

``campaign_updated`` creates or updates the alert of a detected phishing
campaign (see campaign_sync). Cases reach TheHive through the challenge flow
(tasp/services/challenge.py) or when an analyst presses the push button
(``POST /api/submissions/<id>/ticket/``). IOC-group cases no longer get an
automatic alert on ``case_finalised``: it carried only a one-line summary, and
the button builds the full ticket."""
from __future__ import annotations

from case_handler.models import Campaign
from common.clients import get_s3_client
from common.http_client import make_session
from connectors.base import (
    EVENT_CAMPAIGN_UPDATED,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
)
from connectors.contrib.thehive.campaign_client import HiveClient
from connectors.contrib.thehive.campaign_sync import sync_campaign


# What the integration user needs: create the alert, then add observables and
# files to it. A lapsed license silently drops the last two.
REQUIRED_PERMISSIONS = ("manageAlert/create", "manageAlert/update", "manageObservable")


def _email_settings() -> tuple[str, tuple[str, ...]]:
    """The UI base URL for links, and the organisation's own domains (never IOCs)."""
    from settings.config import get_section

    email = get_section("email") or {}
    ui_base = (email.get("links", {}).get("submissions") or "").removesuffix("/submissions").rstrip("/")
    domains = {email.get("content", {}).get("global_domain", "")}
    username = (email.get("smtp", {}).get("username") or "")
    if "@" in username:
        domains.add(username.rsplit("@", 1)[1])
    return ui_base, tuple(sorted(d.lower() for d in domains if d))


class TheHiveConnector(Connector):
    manifest = ConnectorManifest(
        name="thehive",
        version="1.2.0",
        author="Thales CERT",
        category="Incident Response",
        description="TheHive alerts for challenged cases and phishing campaigns.",
        config_schema=(
            ConfigField("url", "url", required=True),
            ConfigField("api_key", "secret", required=True),
            ConfigField("certificate_path", "str",
                        help="CA bundle path; empty = system trust store"),
        ),
        events=(EVENT_CAMPAIGN_UPDATED,),
    )

    def on_campaign_updated(self, event) -> None:
        url, key = self.config.get("url"), self.config.get("api_key")
        if not url or not key:
            return
        ui_base, own_domains = _email_settings()
        sync_campaign(
            Campaign.objects.get(pk=event.campaign_id),
            HiveClient(url, key, verify=self.config.get("certificate_path") or True),
            get_s3_client(), ui_base=ui_base, own_domains=own_domains,
        )

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
            granted = response.json().get("permissions")
            if isinstance(granted, list):
                missing = [p for p in REQUIRED_PERMISSIONS if p not in granted]
                if missing:
                    return HealthStatus(
                        ok=False,
                        detail="authenticated, but missing TheHive permissions: "
                               + ", ".join(missing) + " (expired license or wrong profile?)",
                    )
            return HealthStatus(ok=True, detail="authenticated")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=str(exc))
