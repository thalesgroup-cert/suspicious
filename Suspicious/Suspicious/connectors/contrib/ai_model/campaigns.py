"""Phishing-campaign detection for the ai_model connector, read from the case's AiAssessment.

A campaign is a group of similar dangerous mails (ChromaDB similarity over the assessment's
campaign embedding). Membership lives in the database."""
from __future__ import annotations

import json
import logging
import math
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


def collection_mismatch(collection_name: str) -> str | None:
    """A sentence when the chromadb cleanup connector is set to another collection than
    ``collection_name``, the one detection writes to (so the 15-day window is not enforced), else
    None. Never raises: it feeds a health message and a log line."""
    try:
        if not get_state("chromadb").enabled:
            return None
        watched = registry.instantiate("chromadb").config.get("collection_name", _DEFAULT_COLLECTION_NAME)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Collection mismatch check failed: %s", type(exc).__name__)
        return None
    if watched == collection_name:
        return None
    return (
        f"The chromadb connector is set to collection '{watched}', but campaign detection stores "
        f"mails in '{collection_name}', so old campaign documents are not removed. "
        f"Set collection_name of the chromadb connector to '{collection_name}'."
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
        isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) for x in vector
    )


def _others(similar: dict, doc_id: str) -> dict:
    """The neighbours without ``doc_id``: a rerun finds the case's own document, stored the first time."""
    keep = [i for i, found in enumerate(similar["ids"][0]) if found != doc_id]
    return {
        key: [[similar[key][0][i] for i in keep]]
        for key in ("ids", "embeddings", "metadatas", "documents", "distances")
    }


def _after_rows(case: Case, campaign: Campaign, failure: str, step) -> None:
    # The rows are committed and the caller announces the campaign: a failure here is logged,
    # never raised. A redelivery of the task repeats these steps.
    try:
        step()
    except Exception as exc:  # noqa: BLE001
        logger.error("Case %s is in campaign %s but %s: %s", case.id, campaign.ref, failure, type(exc).__name__)


def _placed(case: Case) -> tuple[Campaign, list[int]] | None:
    """The campaign ``case`` is already a member of and its member case ids, else None."""
    member = CampaignMember.objects.select_related("campaign").filter(case=case).first()
    if member is None:
        return None
    return member.campaign, list(member.campaign.members.values_list("case_id", flat=True))


def _store_and_tag(case: Case, campaign: Campaign, member_ids: list[int], full: dict | None,
                   extra: dict, collection) -> None:
    if full is not None:
        _after_rows(case, campaign, "its document was not stored", lambda: add_to_suspicious_collection(
            full, "", campaign.ref, case.id, collection, extra_metadata=extra
        ))
    _after_rows(case, campaign, "the members were not tagged", lambda: set_campaign_ref(
        collection, [f"case-{c}" for c in member_ids], campaign.ref
    ))


def _title(docs: dict, case: Case) -> str:
    try:
        return get_most_common_subject(docs)[:255]
    except Exception:  # noqa: BLE001 — a title is not worth losing the campaign
        mail = getattr(getattr(case, "fileOrMail", None), "mail", None)
        return (getattr(mail, "subject", "") or "Phishing campaign")[:255]


def detect_campaign(
    case: Case, assessment: AiAssessment, text: str, headers: dict, profile: CampaignProfile, collection
) -> Campaign | None:
    """Return the campaign ``case`` just created, joined or is already in, else None.
    CampaignStoreUnavailable when Chroma fails or the lock is busy before the membership rows are
    written.

    A case already in a campaign (a redelivery, maybe after a worker was killed once the rows
    committed) gets its document stored if absent and the members tagged, and its campaign is
    returned again so the caller announces it once more.

    Not to be called inside an outer transaction.atomic(): the lock would be released before
    the member rows commit, and a concurrent sibling would not see them."""
    valid = bool(assessment.campaign_embedding.strip()) and _is_vector(assessment.campaign_embedding)
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
    } if valid else None
    extra = {"embedding_version": profile.embedding_version}

    placed = _placed(case)
    if placed is not None:
        campaign, member_ids = placed
        _store_and_tag(case, campaign, member_ids, full, extra, collection)
        logger.info("Case %s is already in campaign %s.", case.id, campaign.ref)
        return campaign
    if not assessment.campaign_embedding.strip():
        return None
    if not valid:
        logger.warning("Case %s: the campaign embedding is not a list of numbers; not stored.", case.id)
        return None
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
        # Another task for this case may have placed it while this one waited.
        placed = _placed(case)
        if placed is not None:
            campaign, member_ids = placed
        else:
            with _store_unavailable(failed):
                # No embedding_version filter: for cmp-e1 the live collection holds only that
                # version and older documents carry no tag. A later profile uses its own
                # collection, suspicious_mails__<embedding_version> (spec C28), which keeps the
                # versions apart.
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
            logger.info("Case %s is in campaign %s (%d members).", case.id, campaign.ref, members)

        _store_and_tag(case, campaign, member_ids, full, extra, collection)
        _after_rows(case, campaign, "the detection lock was not released", lock.close)
    return campaign
