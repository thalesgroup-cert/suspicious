"""Phishing-campaign detection for the ai_model connector, read from the case's AiAssessment.

A campaign is a group of similar dangerous mails (ChromaDB similarity over the assessment's
campaign embedding). Membership lives in the database."""
from __future__ import annotations

import json
import logging
from collections import Counter
from contextlib import ExitStack, contextmanager

from django.db import transaction

from ai_model.campaign_profile import CampaignProfile
from ai_model.models import AiAssessment
from case_handler.models import Campaign, CampaignMember, Case
from common.clients import get_chroma_client
from common.locks import cache_lock
from connectors.contrib.chromadb.connector import _DEFAULT_COLLECTION_NAME
from connectors.contrib.thehive.utils import (
    extract_sender_domain_from_headers,
    get_most_common_subject,
    get_phishing_campaign,
    is_domain_in_campaign_allow_list,
)
from connectors.delivery import get_state
from connectors.registry import registry
from score_process.score_utils.chromadb_utils import (
    add_to_suspicious_collection,
    get_similar_dangerous_mails,
    get_suspicious_collection,
    set_campaign_ref,
)

logger = logging.getLogger("connectors.contrib.ai_model")


class CampaignStoreUnavailable(Exception):
    """A failure before any rows exist; the same call can be retried (store down or lock busy)."""


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


def collection_mismatch(profile: CampaignProfile) -> str | None:
    """A sentence when the chromadb cleanup connector runs against another collection than the
    one detection writes to (so the 15-day window is not enforced), else None. Never raises: it
    feeds a health message and a log line."""
    try:
        if not get_state("chromadb").enabled:
            return None
        watched = registry.instantiate("chromadb").config.get("collection_name", _DEFAULT_COLLECTION_NAME)
    except Exception:  # noqa: BLE001
        return None
    if watched == profile.collection_name:
        return None
    return (
        f"The chromadb connector cleans up collection '{watched}', but campaign detection stores "
        f"mails in '{profile.collection_name}', so old campaign documents are not removed. "
        f"Set collection_name of the chromadb connector to '{profile.collection_name}'."
    )


def _case_ids(docs: dict) -> list[int]:
    ids = []
    for meta in docs["metadatas"][0]:
        try:
            ids.append(int(meta["suspicious_case_id"]))
        except (KeyError, TypeError, ValueError):
            continue
    return list(dict.fromkeys(ids))


def _is_vector(raw: str) -> bool:
    try:
        vector = json.loads(raw)
    except ValueError:
        return False
    return isinstance(vector, list) and bool(vector) and all(
        isinstance(x, (int, float)) and not isinstance(x, bool) for x in vector
    )


def _others(similar: dict, doc_id: str) -> dict:
    """The neighbours without ``doc_id``: a rerun finds the case's own document, stored the first time."""
    keep = [i for i, found in enumerate(similar["ids"][0]) if found != doc_id]
    return {
        key: [[similar[key][0][i] for i in keep]]
        for key in ("ids", "embeddings", "metadatas", "documents", "distances")
    }


def _after_rows(case: Case, campaign: Campaign, failure: str, step) -> None:
    # The rows are committed: a retry would stop at the member guard and lose the event, so a
    # failure here is logged, never raised.
    try:
        step()
    except Exception as exc:  # noqa: BLE001
        logger.error("Case %s is in campaign %s but %s: %s", case.id, campaign.ref, failure, type(exc).__name__)


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
    when Chroma fails or the lock is busy before the membership rows are written.

    Not to be called inside an outer transaction.atomic(): the lock would be released before
    the member rows commit, and a concurrent sibling would not see them."""
    if CampaignMember.objects.filter(case=case).exists():
        return None  # delivered more than once; already placed
    if not assessment.campaign_embedding.strip():
        return None
    if not _is_vector(assessment.campaign_embedding):
        logger.warning("Case %s: the campaign embedding is not a list of numbers; not stored.", case.id)
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
    with ExitStack() as lock:
        try:
            lock.enter_context(cache_lock("campaign:detect", ttl=120, wait=90))
        except RuntimeError as exc:
            raise CampaignStoreUnavailable("campaign lock timed out") from exc
        with _store_unavailable(failed):
            similar = get_similar_dangerous_mails(
                assessment.campaign_embedding, collection, n_results=profile.neighbours
            )
            docs = (
                get_phishing_campaign(
                    _others(similar, f"case-{case.id}"), profile.distance_threshold, profile.min_members
                )
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
            members = campaign.members.count()

        _after_rows(case, campaign, "its document was not stored", lambda: add_to_suspicious_collection(
            full, "", campaign.ref, case.id, collection, extra_metadata=extra
        ))
        _after_rows(case, campaign, "the members were not tagged", lambda: set_campaign_ref(
            collection, [f"case-{c}" for c in member_ids], campaign.ref
        ))
        _after_rows(case, campaign, "the detection lock was not released", lock.close)
    logger.info("Case %s is in campaign %s (%d members).", case.id, campaign.ref, members)
    return campaign
