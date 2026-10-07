"""Phishing-campaign detection, run once per case when it is finalised.

A campaign is a group of similar dangerous mails (ChromaDB similarity over the
AI analyzer's embedding). Membership lives in the database; connectors such as
TheHive consume the ``campaign_updated`` event this module emits.
"""
from __future__ import annotations

import logging
from collections import Counter

from case_handler.models import Campaign, CampaignMember, Case
from common.clients import get_chroma_client
from common.locks import cache_lock
from connectors.base import EVENT_CAMPAIGN_UPDATED
from connectors.contrib.thehive.utils import (
    extract_sender_domain_from_headers,
    get_most_common_subject,
    get_phishing_campaign,
    is_domain_in_campaign_allow_list,
)
from connectors.dispatch import emit
from score_process.score_utils.chromadb_utils import (
    add_to_suspicious_collection,
    get_similar_dangerous_mails,
    get_suspicious_collection,
    set_campaign_ref,
)

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

DANGEROUS_MALSCORE_THRESHOLD = 6.5
_AI_ANALYZER_PREFIX = "AI_Mail"


def ai_full_report(case: Case) -> dict | None:
    """The AI mail analyzer's full report for this case, if it succeeded."""
    from cortex_job.models import AnalyzerReport

    report = (
        AnalyzerReport.objects.filter(
            analyzer__name__startswith=_AI_ANALYZER_PREFIX,
            case_jobs__case_id=case.id, status="Success",
        ).order_by("-id").first()
    )
    full = report.report_full if report else None
    return full if isinstance(full, dict) and full.get("report") else None


def _case_ids(docs: dict) -> list[int]:
    ids = []
    for meta in docs["metadatas"][0]:
        try:
            ids.append(int(meta["suspicious_case_id"]))
        except (KeyError, TypeError, ValueError):
            continue
    return list(dict.fromkeys(ids))


def _title(docs: dict, case: Case) -> str:
    try:
        return get_most_common_subject(docs)[:255]
    except Exception:  # noqa: BLE001 — a title is not worth losing the campaign
        mail = getattr(getattr(case, "fileOrMail", None), "mail", None)
        return (getattr(mail, "subject", "") or "Phishing campaign")[:255]


def detect_campaign(case: Case) -> Campaign | None:
    """Return the campaign ``case`` just created or joined, else None."""
    if CampaignMember.objects.filter(case=case).exists():
        return None  # reconciled more than once; already placed
    full = ai_full_report(case)
    if not full:
        return None
    try:
        collection = get_suspicious_collection(get_chroma_client())
    except Exception as exc:  # noqa: BLE001
        logger.error("Campaign detection skipped for case %s: ChromaDB unavailable (%s)", case.id, exc)
        return None

    if float(full.get("malscore") or 0) <= DANGEROUS_MALSCORE_THRESHOLD:
        add_to_suspicious_collection(full, "", "", case.id, collection)
        return None

    sender_domain = extract_sender_domain_from_headers(full["report"].get("analyzed_mail_headers", {}))
    if sender_domain and is_domain_in_campaign_allow_list(sender_domain):
        logger.info("Sender domain %r is allow-listed; no campaign detection for case %s.", sender_domain, case.id)
        return None

    embedding = full["report"].get("email_embedding")
    # Mails of one campaign finalise in parallel: decide membership one at a time.
    with cache_lock("campaign:detect", ttl=120, wait=90):
        similar = get_similar_dangerous_mails(embedding, collection, n_results=20) if embedding else {}
        docs = get_phishing_campaign(similar) if similar.get("ids") else None
        if not docs:
            add_to_suspicious_collection(full, "", "", case.id, collection)
            return None

        member_ids = _case_ids(docs)
        known = Counter(
            CampaignMember.objects.filter(case_id__in=member_ids).values_list("campaign_id", flat=True)
        )
        campaign = (
            Campaign.objects.get(pk=min(known, key=lambda cid: (-known[cid], cid)))
            if known else Campaign.objects.create(title=_title(docs, case))
        )
        existing = set(Case.objects.filter(id__in=member_ids + [case.id]).values_list("id", flat=True))
        for cid in member_ids + [case.id]:
            if cid in existing:
                CampaignMember.objects.get_or_create(case_id=cid, defaults={"campaign": campaign})

        add_to_suspicious_collection(full, "", campaign.ref, case.id, collection)
        set_campaign_ref(collection, [f"case-{c}" for c in member_ids + [case.id]], campaign.ref)
    logger.info("Case %s is in campaign %s (%d members).", case.id, campaign.ref, campaign.members.count())
    return campaign


def run_for_case(case: Case) -> None:
    """Finalisation hook: detect, then tell the connectors. Never raises."""
    try:
        campaign = detect_campaign(case)
        if campaign:
            emit(EVENT_CAMPAIGN_UPDATED, case, campaign_id=campaign.id)
    except Exception:  # noqa: BLE001 — must not break finalisation
        logger.exception("Campaign detection failed for case %s", getattr(case, "id", "?"))
