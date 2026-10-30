"""Phishing-campaign detection for the ai_model connector: case_handler.campaigns ported to
read the case's AiAssessment instead of the Cortex AI report.

A campaign is a group of similar dangerous mails (ChromaDB similarity over the assessment's
campaign embedding). Membership lives in the database."""
from __future__ import annotations

import logging
from collections import Counter
from contextlib import contextmanager

from django.db import transaction

from ai_model.campaign_profile import CampaignProfile
from ai_model.models import AiAssessment
from case_handler.models import Campaign, CampaignMember, Case
from common.clients import get_chroma_client
from common.locks import cache_lock
from connectors.contrib.thehive.utils import (
    extract_sender_domain_from_headers,
    get_most_common_subject,
    get_phishing_campaign,
    is_domain_in_campaign_allow_list,
)
from score_process.score_utils.chromadb_utils import (
    add_to_suspicious_collection,
    get_similar_dangerous_mails,
    get_suspicious_collection,
    set_campaign_ref,
)

logger = logging.getLogger("connectors.contrib.ai_model")


class CampaignStoreUnavailable(Exception):
    """The campaign store failed before any membership was written; detection can be retried."""


@contextmanager
def _store_unavailable(what: str):
    try:
        yield
    except Exception as exc:  # noqa: BLE001 -- the Chroma client's failures are many
        # The class name only: a Chroma message can echo the document or a credential.
        raise CampaignStoreUnavailable(f"{what}: {type(exc).__name__}") from exc


def open_collection(profile: CampaignProfile):
    with _store_unavailable("campaign store unavailable"):
        return get_suspicious_collection(get_chroma_client(), profile.collection_name)


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


def detect_campaign(
    case: Case, assessment: AiAssessment, text: str, headers: dict, profile: CampaignProfile, collection
) -> Campaign | None:
    """Return the campaign ``case`` just created or joined, else None. CampaignStoreUnavailable
    when Chroma fails before the membership rows are written."""
    if CampaignMember.objects.filter(case=case).exists():
        return None  # delivered more than once; already placed
    if not assessment.campaign_embedding.strip():
        return None
    # The shape of the Cortex AI report, which the collection helpers read.
    full = {
        "classification": assessment.result,
        "sub_classification": assessment.sub_class,
        "malscore": assessment.score,
        "confidence": assessment.confidence / 100,
        "report": {
            "analyzed_mail_content": text,
            "analyzed_mail_headers": headers,
            "email_embedding": assessment.campaign_embedding,
        },
    }
    extra = {"embedding_version": profile.embedding_version}
    failed = f"campaign store failed for case {case.id}"

    if assessment.result != profile.trigger_class:
        with _store_unavailable(failed):
            add_to_suspicious_collection(full, "", "", case.id, collection, extra_metadata=extra)
        return None

    sender_domain = extract_sender_domain_from_headers(headers)
    if sender_domain and is_domain_in_campaign_allow_list(sender_domain):
        logger.info("Sender domain %r is allow-listed; no campaign detection for case %s.", sender_domain, case.id)
        return None

    # Mails of one campaign finalise in parallel: decide membership one at a time.
    with cache_lock("campaign:detect", ttl=120, wait=90):
        with _store_unavailable(failed):
            similar = get_similar_dangerous_mails(
                assessment.campaign_embedding, collection, n_results=profile.neighbours
            )
            docs = (
                get_phishing_campaign(similar, profile.distance_threshold, profile.min_members)
                if similar.get("ids") else None
            )
            if not docs:
                add_to_suspicious_collection(full, "", "", case.id, collection, extra_metadata=extra)
                return None

        member_ids = list(dict.fromkeys([*_case_ids(docs), case.id]))
        with transaction.atomic():
            known = Counter(
                CampaignMember.objects.filter(case_id__in=member_ids).values_list("campaign_id", flat=True)
            )
            campaign = (
                Campaign.objects.get(pk=min(known, key=lambda cid: (-known[cid], cid)))
                if known else Campaign.objects.create(title=_title(docs, case))
            )
            existing = set(Case.objects.filter(id__in=member_ids).values_list("id", flat=True))
            for cid in member_ids:
                if cid in existing:
                    CampaignMember.objects.get_or_create(case_id=cid, defaults={"campaign": campaign})

        # The rows are written: a retry would stop at the guard above and lose the event, so a
        # store failure here only leaves the Campaigns page short of this mail.
        try:
            add_to_suspicious_collection(full, "", campaign.ref, case.id, collection, extra_metadata=extra)
            set_campaign_ref(collection, [f"case-{c}" for c in member_ids], campaign.ref)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Case %s joined campaign %s but the campaign store was not updated: %s",
                case.id, campaign.ref, type(exc).__name__,
            )
    logger.info("Case %s is in campaign %s (%d members).", case.id, campaign.ref, campaign.members.count())
    return campaign
