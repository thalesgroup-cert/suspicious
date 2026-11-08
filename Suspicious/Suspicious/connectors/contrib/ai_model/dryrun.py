"""Ruling F7: what campaign detection would do with the shadow model's classes.

Geometry comes from the live collection (the campaign embedding does not depend on the
classifier), the candidate's classes from its ShadowResult rows (live or seeded). Reads the
collection only: this module imports no writing helper, creates no Campaign or member row and
emits nothing. Its one write is the case's ShadowCampaignEffect row."""
from __future__ import annotations

import json
from collections import Counter

from ai_model.models import ShadowCampaignEffect, ShadowResult
from case_handler.models import CampaignMember
from connectors.contrib.ai_model.campaigns import _case_ids, _is_vector, _others, _store_unavailable
from connectors.contrib.thehive.utils import (
    extract_sender_domain_from_headers,
    get_phishing_campaign,
    is_domain_in_campaign_allow_list,
)

NEIGHBOURS = 60  # ponytail: neighbours beyond rank 60 are missed (Ruling F7); raise if the table shows it
E = ShadowCampaignEffect.Effect
_KEYS = ("ids", "embeddings", "metadatas", "documents", "distances")


def _record(case, version, effect, member_ids=(), live_campaign_id=None) -> ShadowCampaignEffect:
    row, _ = ShadowCampaignEffect.objects.update_or_create(case=case, version=version, defaults={
        "effect": effect, "member_case_ids": list(member_ids), "live_campaign_id": live_campaign_id,
    })
    return row


def _candidate_dangerous(similar: dict, version, trigger: str) -> dict:
    """The neighbours whose case the candidate called ``trigger``, in the query's shape."""
    ids = _case_ids(similar)
    dangerous = {str(cid) for cid in ShadowResult.objects.filter(
        version=version, case_id__in=ids, result=trigger, error="").values_list("case_id", flat=True)}
    keep = [i for i, meta in enumerate(similar["metadatas"][0])
            if str((meta or {}).get("suspicious_case_id")) in dangerous]
    return {key: [[similar[key][0][i] for i in keep]] for key in _KEYS}


def dry_run_campaign(case, shadow_result, assessment, headers, profile, collection) -> ShadowCampaignEffect:
    """Record the effect for (case, shadow_result.version). CampaignStoreUnavailable when the
    query fails; nothing is recorded then."""
    version = shadow_result.version
    if shadow_result.result != profile.trigger_class:
        return _record(case, version, E.NO_CHECK)
    sender_domain = extract_sender_domain_from_headers(headers)
    if sender_domain and is_domain_in_campaign_allow_list(sender_domain):
        return _record(case, version, E.NO_CHECK)
    embedding = getattr(assessment, "campaign_embedding", "") or ""
    if not _is_vector(embedding):
        return _record(case, version, E.NO_CHECK)

    with _store_unavailable(f"campaign store failed for case {case.id}"):
        similar = collection.query(
            query_embeddings=[json.loads(embedding)], n_results=NEIGHBOURS,
            include=["embeddings", "metadatas", "documents", "distances"],
        )
    if not similar.get("ids"):
        return _record(case, version, E.NONE)
    docs = get_phishing_campaign(
        _candidate_dangerous(_others(similar, f"case-{case.id}"), version, profile.trigger_class),
        profile.distance_threshold, profile.min_members,
    )
    if not docs:
        return _record(case, version, E.NONE)
    neighbours = _case_ids(docs)
    member_ids = list(dict.fromkeys([*neighbours, case.id]))
    # The campaign live detection would pick: the one most of the members are in. Neighbours only:
    # the live task may already have placed the case itself.
    known = Counter(CampaignMember.objects.filter(case_id__in=neighbours).values_list("campaign_id", flat=True))
    if not known:
        return _record(case, version, E.WOULD_CREATE, member_ids)
    return _record(case, version, E.WOULD_JOIN, member_ids, min(known, key=lambda cid: (-known[cid], cid)))
