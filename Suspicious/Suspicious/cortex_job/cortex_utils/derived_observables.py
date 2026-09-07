"""Turn an extractor analyzer's report into new observables in the same case.
See docs/specs/2026-09-07-derived-observables-design.md.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from django.db import transaction

from settings.config import get_config
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

_OBSERVABLE_TYPES = {"url", "domain", "ip", "hash", "mail"}


def _unshorten(full: Any) -> list[tuple[str, str]]:
    if not isinstance(full, dict) or not full.get("found"):
        return []
    url = full.get("url")
    return [(url, "url")] if isinstance(url, str) and url else []


def _qrdecode(full: Any) -> list[tuple[str, str]]:
    if not isinstance(full, dict):
        return []
    out: list[tuple[str, str]] = []
    for entry in full.get("results_list") or []:
        res = entry.get("results") if isinstance(entry, dict) else None
        if not isinstance(res, dict):
            continue
        value, dtype = res.get("data"), str(res.get("data_type") or "").lower()
        if isinstance(value, str) and value and dtype in _OBSERVABLE_TYPES:
            out.append((value, dtype))
    return out


def _blocked(value: str, data_type: str) -> str:
    """Non-empty reason if `value` must not become a live observable."""
    if data_type == "url":
        from api.serializers.submit import _check_no_ssrf_ip
        try:
            _check_no_ssrf_ip(value)
        except ValueError as exc:
            return str(exc) or "SSRF-blocked target"
    if data_type in ("url", "domain"):
        from score_process.scoring.cortex_analyzers.allow_list import check_allow_list
        try:
            allow = check_allow_list(value, data_type)
            for reason in allow.model_dump().values():
                if reason:
                    return f"allow-listed ({reason})"
        except Exception:  # noqa: BLE001 — never block ingestion on an allow-list error
            logger.warning("derived: allow-list check failed for %r", value, exc_info=True)
    return ""


EXTRACTORS: dict[str, Callable[[Any], list[tuple[str, str]]]] = {
    "UnshortenLink_1_2": _unshorten,
    "QrDecode_1_0": _qrdecode,
}


# data_type -> (module, class, value-field). Verified against the observable models.
_MODEL_BY_TYPE = {
    "url": ("url_process.models", "URL", "address"),
    "domain": ("domain_process.models", "Domain", "value"),
    "ip": ("ip_process.models", "IP", "address"),
    "hash": ("hash_process.models", "Hash", "value"),
    "mail": ("email_process.models", "MailAddress", "address"),
}


def _resolve_observable(value: str, data_type: str):
    """Get-or-create the observable model for `value`. None on an unknown type."""
    spec = _MODEL_BY_TYPE.get(data_type)
    if spec is None:
        return None
    from importlib import import_module

    module, cls_name, field = spec
    model = getattr(import_module(module), cls_name)
    obj, _ = model.objects.get_or_create(**{field: value})
    return obj


# IOC-road: ObservableGroupArtifact.Type is upper-cased (URL/IP/HASH/DOMAIN).
_OGA_TYPE = {"url": "URL", "domain": "DOMAIN", "ip": "IP", "hash": "HASH"}

# Mail-road: data_type -> (join model, MailArtifact FK attr, MailArtifact.artifact_type, join FK field)
_MAIL_JOIN = {
    "url": ("ArtifactIsUrl", "artifactIsUrl", "URL", "url"),
    "ip": ("ArtifactIsIp", "artifactIsIp", "IP", "ip"),
    "hash": ("ArtifactIsHash", "artifactIsHash", "Hash", "hash"),
    "domain": ("ArtifactIsDomain", "artifactIsDomain", "Domain", "domain"),
    "mail": ("ArtifactIsMailAddress", "artifactIsMailAddress", "MailAddress", "mail_address"),
}


def _attach_to_case(case, obj, data_type: str) -> None:
    """Link `obj` to `case` the way the rest of the codebase does: an
    ObservableGroupArtifact for an IOC-group case, else a MailArtifact +
    ArtifactIsX join row for a mail case. Idempotent."""
    if getattr(case, "observable_group_id", None):
        art_type = _OGA_TYPE.get(data_type)
        if art_type is None:
            return
        from case_handler.models import ObservableGroupArtifact

        ObservableGroupArtifact.objects.get_or_create(
            group_id=case.observable_group_id, artifact_type=art_type, **{data_type: obj}
        )
        return

    mail = getattr(getattr(case, "fileOrMail", None), "mail", None)
    if mail is None:
        logger.warning("derived: case %s has neither observable_group nor mail", case.pk)
        return

    spec = _MAIL_JOIN.get(data_type)
    if spec is None:
        return
    import mail_feeder.models as mf

    join_cls_name, fk_attr, art_type, join_field = spec
    join_cls = getattr(mf, join_cls_name)
    if mf.MailArtifact.objects.filter(
        mail=mail, artifact_type=art_type, **{f"{fk_attr}__{join_field}": obj}
    ).exists():
        return
    with transaction.atomic():
        ma = mf.MailArtifact.objects.create(mail=mail, artifact_type=art_type)
        join = join_cls.objects.create(artifact=ma, **{join_field: obj})
        setattr(ma, fk_attr, join)
        ma.save(update_fields=[fk_attr])


_PARENT_TYPE_BY_FIELD = {"url": "url", "domain": "domain", "ip": "ip",
                         "hash": "hash", "file": "file"}


def _finished_extractor_reports(case):
    """Success reports for this case's observables whose analyzer is an extractor."""
    from cortex_job.models import AnalyzerReport
    from cortex_job.cortex_utils.case_targets import (
        collect_case_targets, build_analyzer_report_filter,
    )
    targets = collect_case_targets(case)
    if not targets:
        return []
    q = build_analyzer_report_filter(targets)
    return list(
        AnalyzerReport.objects.filter(q, status="Success", analyzer__name__in=EXTRACTORS)
        .select_related("analyzer")
        .order_by("creation_date")
    )


def _report_parent(report):
    """(parent_type, parent_obj) the extractor report was filed against."""
    for field, ptype in _PARENT_TYPE_BY_FIELD.items():
        obj = getattr(report, field, None)
        if obj is not None:
            return ptype, obj
    return None, None


_BAND_RANK = {"Safe": 0, "Inconclusive": 0, "Suspicious": 1, "Dangerous": 2}
_IOC_LEVEL_TO_BAND = {"safe": "Safe", "info": "Inconclusive", "suspicious": "Suspicious",
                      "malicious": "Dangerous", "critical": "Dangerous"}


def _child_band(child_type, child_id) -> str:
    """Score a child observable through the IOC engine (newest report per analyzer)."""
    from cortex_job.models import AnalyzerReport
    from score_process.scoring.observable_engine import score_observable
    from score_process.scoring.sources import source_verdict_from_report

    reports = (AnalyzerReport.objects
               .filter(status="Success", **{f"{child_type}_id": child_id})
               .select_related("analyzer").order_by("-creation_date"))
    seen, svs = set(), []
    for r in reports:
        if r.analyzer_id in seen:
            continue
        seen.add(r.analyzer_id)
        svs.append(source_verdict_from_report(r))
    return score_observable(svs).band if svs else "Inconclusive"


def _parent_band(d) -> str:
    """Parent's current band, read from its observable model's ioc_level
    (IOC road) or artifact_level (mail road)."""
    spec = _MODEL_BY_TYPE.get(d.parent_type)
    if spec is None:
        return "Inconclusive"
    from importlib import import_module

    module, cls_name, _ = spec
    model = getattr(import_module(module), cls_name)
    obj = model.objects.filter(pk=d.parent_id).first()
    lvl = getattr(obj, "ioc_level", "info") if obj else "info"
    return _IOC_LEVEL_TO_BAND.get(str(lvl).lower(), "Inconclusive")


def score_derived_observables(case) -> dict:
    """Score every derived child, persist child_band + escalation_note on the row.
    Return {(parent_type, parent_id): (band, note)} for children that scored
    Suspicious/Dangerous strictly above their parent's current band."""
    out: dict = {}
    for d in case.derived_observables.all():
        band = _child_band(d.child_type, d.child_id)
        d.child_band = band
        note = ""
        rank = _BAND_RANK.get(band, 0)
        if rank >= 1 and rank > _BAND_RANK.get(_parent_band(d), 0):
            note = (f"Escalated to {band}: {d.via_analyzer} extracted "
                    f"{d.child_value} → {band}.")
            out[(d.parent_type, d.parent_id)] = (band, note)
        d.escalation_note = note
        d.save(update_fields=["child_band", "escalation_note"])
    return out


def ingest_derived_observables(case) -> int:
    """Turn this case's finished extractor reports into new observables +
    dispatched jobs. Returns the number of observables newly attached this call.
    0 when disabled or when every child is already attached. Idempotency is per
    (source_report, child_type, child_id) via get_or_create, so a sibling value
    that failed transiently is retried on the next pass.
    """
    # Default-on: only an explicit `false` disables. get_config's cache returns
    # None (not the passed default) for an unset key, so `not ...` can't be used.
    if get_config("derived_observables.enabled", True) is False:
        return 0

    derived_children = {
        (d.child_type, d.child_id) for d in case.derived_observables.all()
    }
    new_count = 0

    for report in _finished_extractor_reports(case):
        parent_type, parent = _report_parent(report)
        if parent is None:
            continue
        if (parent_type, parent.pk) in derived_children:
            continue  # 1-hop cap

        fn = EXTRACTORS[report.analyzer.name]
        for value, data_type in fn(report.report_full):
            try:
                reason = _blocked(value, data_type)
                if reason:
                    logger.info("derived: skip %r (%s)", value, reason)
                    continue
                obj = _resolve_observable(value, data_type)
                if obj is None:
                    continue
                _attach_to_case(case, obj, data_type)
                _, created = case.derived_observables.get_or_create(
                    source_report=report, child_type=data_type, child_id=obj.pk,
                    defaults=dict(
                        via_analyzer=report.analyzer.name,
                        parent_type=parent_type, parent_id=parent.pk,
                        child_value=value[:512],
                    ),
                )
                if not created:
                    continue
                CortexJob().launch_cortex_jobs(value=obj, data_type=data_type, case=case)
                new_count += 1
            except Exception as exc:  # noqa: BLE001 — one bad value must not abort the pass
                logger.warning(
                    "derived: skip %r: %s", value, exc, exc_info=True
                )
                continue

    return new_count
