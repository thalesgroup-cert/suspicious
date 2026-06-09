import logging
from typing import Any, Optional
from urllib.parse import urlparse

import requests
from django.db import transaction
from django.utils.dateparse import parse_date, parse_datetime

from domain_process.models import Domain
from settings.models import (
    WatcherLegitDomain,
    WatcherMonitoredDomain,
)

logger = logging.getLogger("tasp.cron.watcher")


def _watcher_conf() -> dict:
    from settings.config import get_section
    return get_section("integrations.watcher")


class WatcherConfig:
    def __init__(
        self,
        url: str,
        api_key: str,
        enabled: bool = True,
        timeout: int = 10,
        verify_ssl: bool = True,
    ):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.enabled = enabled
        self.timeout = timeout
        self.verify_ssl = verify_ssl


def get_watcher_config() -> Optional[WatcherConfig]:
    watcher_conf = _watcher_conf()
    if not watcher_conf.get("enabled", False):
        logger.info("Watcher sync is disabled in settings.json")
        return None

    url = watcher_conf.get("url")
    api_key = watcher_conf.get("api_key")
    timeout = watcher_conf.get("timeout", 10)
    verify_ssl = watcher_conf.get("verify_ssl", True)

    if not url or not api_key:
        logger.error("Watcher configuration is incomplete")
        return None

    return WatcherConfig(
        url=url,
        api_key=api_key,
        enabled=True,
        timeout=timeout,
        verify_ssl=verify_ssl,
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
                verify=self.config.verify_ssl,
            )

            if response.status_code >= 400:
                logger.error(
                    "Watcher API error status=%s url=%s body=%s",
                    response.status_code,
                    response.url,
                    response.text[:1000],
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

    def get_legitimates(self) -> list[dict[str, Any]]:
        return self._get_paginated("/api/common/legitimate_domains/")


def extract_domain_value(value: str) -> str:
    value = (value or "").strip().lower()
    if not value:
        return ""

    # Refang defanged indicators (e.g. "example[.]com", "hxxp://...", "[:]")
    refanged = (
        value.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("hxxp://", "http://")
        .replace("hxxps://", "https://")
    )

    try:
        parsed = urlparse(refanged if "://" in refanged else f"https://{refanged}")
        return (parsed.hostname or refanged).strip().lower()
    except ValueError:
        return refanged


def get_or_create_domain(domain_value: str) -> Optional[Domain]:
    domain_value = (domain_value or "").strip().lower()
    if not domain_value:
        return None

    domain_obj = Domain.objects.filter(value__iexact=domain_value).first()
    if domain_obj:
        return domain_obj

    return Domain.objects.create(value=domain_value)


def map_site_status(site_payload: dict[str, Any]) -> str:
    monitored = site_payload.get("monitored")
    legitimacy = site_payload.get("legitimacy")
    web_status = site_payload.get("web_status")

    return f"monitored={monitored}; legitimacy={legitimacy}; web_status={web_status}"


def map_legit_status(legit_payload: dict[str, Any]) -> str:
    return str(legit_payload.get("status", "") or "legit")


def parse_any_datetime(value):
    if not value:
        return None

    dt = parse_datetime(value)
    if dt is not None:
        return dt

    d = parse_date(value)
    if d is not None:
        from datetime import datetime, time
        return datetime.combine(d, time.min)

    return None


@transaction.atomic
def sync_site(site_payload: dict[str, Any]) -> None:
    watcher_id = site_payload.get("id")
    site_value = (
        site_payload.get("domain_name")
        or site_payload.get("url")
        or site_payload.get("domain")
        or ""
    )
    domain_value = extract_domain_value(site_value)

    if watcher_id is None or not domain_value:
        logger.warning(
            "Skipping invalid site payload: watcher_id=%r domain_value=%r payload=%s",
            watcher_id,
            domain_value,
            site_payload,
        )
        return

    domain_obj = get_or_create_domain(domain_value)
    status = map_site_status(site_payload)

    remote_last_update = parse_any_datetime(
        site_payload.get("updated_at") or site_payload.get("created_at")
    )

    monitored_obj, created = WatcherMonitoredDomain.objects.update_or_create(
        watcher_id=watcher_id,
        defaults={
            "domain": domain_obj,
            "status": status,
            "remote_last_update": remote_last_update,
            "raw_payload": site_payload,
        },
    )

    logger.info(
        "Synced site watcher_id=%s domain=%s created=%s",
        monitored_obj.watcher_id,
        domain_value,
        created,
    )


@transaction.atomic
def sync_legit(legit_payload: dict[str, Any]) -> None:
    watcher_id = legit_payload.get("id")
    legit_value = (
        legit_payload.get("domain_name")
        or legit_payload.get("url")
        or legit_payload.get("domain")
        or ""
    )
    domain_value = extract_domain_value(legit_value)

    if watcher_id is None or not domain_value:
        logger.warning(
            "Skipping invalid legit payload: watcher_id=%r domain_value=%r payload=%s",
            watcher_id,
            domain_value,
            legit_payload,
        )
        return

    domain_obj = get_or_create_domain(domain_value)
    status = map_legit_status(legit_payload)
    remote_last_update = parse_any_datetime(
        legit_payload.get("updated_at") or legit_payload.get("created_at")
    )

    legit_obj, created = WatcherLegitDomain.objects.update_or_create(
        watcher_id=watcher_id,
        defaults={
            "domain": domain_obj,
            "status": status,
            "remote_last_update": remote_last_update,
            "raw_payload": legit_payload,
        },
    )

    logger.info(
        "Synced legit watcher_id=%s domain=%s created=%s",
        legit_obj.watcher_id,
        domain_value,
        created,
    )


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

        try:
            legits = client.get_legitimates()
            logger.info("Fetched %s legitimate domains from Watcher", len(legits))

            for legit_payload in legits:
                try:
                    sync_legit(legit_payload)
                except Exception:
                    logger.exception("Failed to sync legit payload: %s", legit_payload)
        except requests.RequestException:
            logger.exception("Failed to fetch legitimate domains from Watcher")

        logger.info("Watcher sync completed")

    except requests.RequestException:
        logger.exception("Watcher API request failed")
    except Exception:
        logger.exception("Unexpected Watcher sync failure")