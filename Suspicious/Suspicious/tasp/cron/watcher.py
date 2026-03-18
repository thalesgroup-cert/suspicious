import json
import logging
from typing import Any, Optional
from urllib.parse import urlparse

import requests
from django.db import transaction
from django.utils.dateparse import parse_datetime

from domain_process.models import Domain
from settings.models import (
    WatcherLegitDomain,
    WatcherMonitoredDomain,
)

logger = logging.getLogger("cron.watcher")
CONFIG_PATH = "/app/settings.json"


with open(CONFIG_PATH, "r") as f:
    settings_data = json.load(f)

watcher_conf = settings_data.get("watcher", {})


class WatcherConfig:
    def __init__(self, url: str, api_key: str, enabled: bool = True, timeout: int = 10):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.enabled = enabled
        self.timeout = timeout


def get_watcher_config() -> Optional[WatcherConfig]:
    if not watcher_conf.get("enabled", False):
        logger.info("Watcher sync is disabled in settings.json")
        return None

    url = watcher_conf.get("url")
    api_key = watcher_conf.get("api_key")
    timeout = watcher_conf.get("timeout", 10)

    if not url or not api_key:
        logger.error("Watcher configuration is incomplete")
        return None

    return WatcherConfig(
        url=url,
        api_key=api_key,
        enabled=True,
        timeout=timeout,
    )


class WatcherClient:
    def __init__(self, config: WatcherConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {self.config.api_key}",
            "Accept": "application/json",
        })

    def _get_paginated(self, path: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        page = 1

        while True:
            url = f"{self.config.url}{path}"
            response = self.session.get(
                url,
                params={"page": page, "page_size": 100},
                timeout=self.config.timeout,
            )
            response.raise_for_status()

            payload = response.json()
            page_results = payload.get("results", [])
            results.extend(page_results)

            if not payload.get("next"):
                break

            page += 1

        return results

    def get_sites(self) -> list[dict[str, Any]]:
        return self._get_paginated("/api/site_monitoring/site/")


def extract_domain_value(site_value: str) -> str:
    if not site_value:
        return ""

    parsed = urlparse(site_value if "://" in site_value else f"https://{site_value}")
    return (parsed.hostname or site_value).lower()


def get_or_create_domain(domain_value: str) -> Optional[Domain]:
    domain_value = (domain_value or "").strip().lower()
    if not domain_value:
        return None

    domain_obj = Domain.objects.filter(value__iexact=domain_value).first()
    if domain_obj:
        return domain_obj

    return Domain.objects.create(value=domain_value)


def map_site_status(site_payload: dict[str, Any]) -> str:
    return str(site_payload.get("status", "") or "")


def is_legit_site(site_payload: dict[str, Any]) -> bool:
    """
    Adjust this rule to your Watcher payload.
    Example:
    - legit if explicitly marked non-malicious
    - or if category/type/status says legit
    """
    if site_payload.get("is_malicious") is False:
        return True

    status = str(site_payload.get("status", "")).lower()
    return status in {"legit", "safe", "clean"}


@transaction.atomic
def sync_site(site_payload: dict[str, Any]) -> None:
    watcher_id = site_payload.get("id")
    site_value = site_payload.get("site") or site_payload.get("url") or site_payload.get("domain") or ""
    domain_value = extract_domain_value(site_value)

    if not watcher_id or not domain_value:
        logger.warning("Skipping invalid site payload: %s", site_payload)
        return

    domain_obj = get_or_create_domain(domain_value)
    status = map_site_status(site_payload)
    remote_last_update = parse_datetime(site_payload.get("updated_at")) if site_payload.get("updated_at") else None

    monitored_obj, _ = WatcherMonitoredDomain.objects.update_or_create(
        watcher_id=watcher_id,
        defaults={
            "domain": domain_obj,
            "status": status,
            "remote_last_update": remote_last_update,
            "raw_payload": site_payload,
        },
    )

    if is_legit_site(site_payload):
        WatcherLegitDomain.objects.update_or_create(
            watcher_id=watcher_id,
            defaults={
                "domain": domain_obj,
                "status": status,
                "remote_last_update": remote_last_update,
                "raw_payload": site_payload,
            },
        )
    else:
        WatcherLegitDomain.objects.filter(watcher_id=watcher_id).delete()

    logger.info("Synced site watcher_id=%s domain=%s", monitored_obj.watcher_id, domain_value)



def run_watcher_sync() -> None:
    config = get_watcher_config()
    if config is None:
        return

    client = WatcherClient(config)

    logger.info("Starting Watcher sync")

    try:
        sites = client.get_sites()
        logger.info("Fetched %s sites from Watcher", len(sites))

        for site_payload in sites:
            try:
                sync_site(site_payload)
            except Exception:
                logger.exception("Failed to sync site payload: %s", site_payload)

        logger.info("Watcher sync completed")

    except requests.RequestException:
        logger.exception("Watcher API request failed")
    except Exception:
        logger.exception("Unexpected Watcher sync failure")