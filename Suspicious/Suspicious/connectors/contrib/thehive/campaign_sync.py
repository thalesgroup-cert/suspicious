"""Bring a TheHive alert in line with a Campaign: create it, or add what is new."""
from __future__ import annotations

import hashlib
import logging

import requests

from case_handler.models import Campaign
from common.locks import cache_lock
from connectors.contrib.thehive.campaign_alert import (
    CampaignContent,
    MemberInfo,
    MemberMaterial,
    build_content,
)
from connectors.contrib.thehive.campaign_iocs import extract_iocs
from connectors.contrib.thehive.campaign_material import fetch_mail_material, select_attachments

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

CONNECTOR = "thehive"
# ponytail: every sync re-reads all members from MinIO; make it incremental if
# campaigns routinely pass a hundred mails.
MAX_MEMBERS = 100


def _read_preview(store, mail) -> bytes:
    bucket, key = mail.preview_bucket, mail.preview_object_key
    if not (bucket and key):
        return b""
    try:
        with store.open(bucket, key) as stream:
            return stream.read()
    except Exception as exc:  # noqa: BLE001 — the preview is optional evidence
        logger.warning("mail %s: cannot read its preview %s/%s: %s", mail.mail_id, bucket, key, exc)
        return b""


def load_member(case, store, own_domains) -> MemberMaterial | None:
    mail = getattr(case.fileOrMail, "mail", None) if case.fileOrMail else None
    if mail is None:
        return None
    material = fetch_mail_material(store, str(mail.mail_id))
    kept, skipped = select_attachments(material.attachments)
    iocs = extract_iocs(material, kept, skipped, own_domains=own_domains)
    info = MemberInfo(
        case_id=case.id, reporter=case.reporter.email or case.reporter.username,
        verdict=str(case.results), malscore=float(case.score_ai or 0),
        subject=mail.subject, created_at=case.creation_date,
    )
    return MemberMaterial(info, material, kept, skipped, iocs, _read_preview(store, mail))


def _update(client, alert_id: str, content: CampaignContent, new_case_ids: list[int]) -> None:
    existing = client.list_observables(alert_id)
    have_files = {h for o in existing if o["dataType"] == "file"
                  for h in (o.get("attachment") or {}).get("hashes", [])[:1]}
    by_key = {(o["dataType"], o.get("data")): o for o in existing if o["dataType"] != "file"}
    for obs in content.observables:
        found = by_key.get((obs["dataType"], obs["data"]))
        if found is None:
            client.add_observable(alert_id, obs)
        elif missing := [t for t in obs["tags"] if t not in found.get("tags", [])]:
            client.add_observable_tags(found["_id"], [*found.get("tags", []), *missing])
    for part in content.files:
        if hashlib.sha256(part.data).hexdigest() not in have_files:
            client.add_file_observable(alert_id, part, content.tlp, content.pap)
    client.patch_alert(alert_id, {
        "title": content.title, "description": content.description,
        "severity": content.severity, "tags": content.tags,
    })
    if new_case_ids:
        client.add_comment(alert_id, "New mail(s) joined the campaign: cases "
                           + ", ".join(f"#{c}" for c in new_case_ids))


def sync_campaign(campaign: Campaign, client, store, *, ui_base: str, own_domains=()) -> str:
    """Returns "created", "updated" or "up-to-date". Raises on any TheHive error
    so the connector framework retries; a retry is safe (observables and files
    are diffed against the alert, and alerts are unique on their sourceRef)."""
    with cache_lock(f"thehive:campaign:{campaign.pk}", ttl=600, wait=300):
        campaign.refresh_from_db()
        members = list(campaign.members.select_related("case__reporter", "case__fileOrMail__mail"))
        pending = [m for m in members if CONNECTOR not in m.synced]
        alert_id = campaign.external_refs.get(CONNECTOR)
        alert = client.get_alert(alert_id) if alert_id else client.find_by_source_ref(campaign.ref)
        if alert is not None and not pending:
            return "up-to-date"

        loaded = [load_member(m.case, store, own_domains) for m in members[-MAX_MEMBERS:]]
        content = build_content(campaign, [m for m in loaded if m], ui_base=ui_base)
        if alert is None:
            alert, outcome = client.create_alert(content), "created"
        else:
            _update(client, alert["_id"], content, [m.case_id for m in pending])
            outcome = "updated"

        # The Attachments tab holds the rendered mails; the files themselves are file
        # observables. Best effort: a rejected file must not fail the sync.
        try:
            added, present, failed = client.add_attachments(alert["_id"], content.attachments)
        except requests.RequestException as exc:
            added, present, failed = 0, 0, [str(exc)]
        not_sent = sum(len(m.skipped) for m in loaded if m)
        logger.info(
            "Campaign %s: %d file(s) attached to the alert, %d already there, %d failed; "
            "%d file(s) skipped (too large, empty, duplicate or tracking pixel).",
            campaign.ref, added, present, len(failed), not_sent,
        )
        if failed:
            logger.warning("Campaign %s: could not attach %d file(s): %s",
                           campaign.ref, len(failed), "; ".join(failed[:3]))

        campaign.external_refs = {**campaign.external_refs, CONNECTOR: alert["_id"]}
        campaign.save(update_fields=["external_refs", "updated_at"])
        for m in members:
            if CONNECTOR not in m.synced:
                m.synced = [*m.synced, CONNECTOR]
                m.save(update_fields=["synced"])
        logger.info("Campaign %s %s in TheHive (%s).", campaign.ref, outcome, alert["_id"])
        return outcome
