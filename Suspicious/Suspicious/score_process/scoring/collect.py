"""Read the DB and build the typed inputs the pure engine consumes.

Reuses the existing per-artifact processing (which still persists analyzer
reports and artifact scores) but converts its parallel score/confidence output
into Signal objects, plus the AI signal and the deny-list flag.
"""
import logging

from score_process.scoring.engine import (
    Signal, AiSignal, Vote, MALICIOUS_SCORE_THRESHOLD, CONF_FLOOR, band, _BAND_RANK,
)
from score_process.scoring.processing import (
    process_file_ioc, process_mail, process_ioc,
)
from score_process.scoring.case_score_calculation import (
    get_deny_listed_domains_set,
    _check_mail_artifacts_for_deny_list,
    _is_address_deny_listed,
)
from case_handler.models import Result
from settings.config import get_config

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def _signals_from(scores, confidences, offset, source):
    """Turn the new (score, confidence) pairs appended since `offset` into
    Signals. is_malicious is the per-artifact equivalent of the old per-report
    vote — score-only by design, so the malicious-vote override in score_case
    can fire on a high-score artifact regardless of its confidence."""
    out = []
    for score, conf in zip(scores[offset:], confidences[offset:]):
        normalized_confidence = min(round(conf), 100)
        out.append(Signal(
            source=source, score=score, confidence=normalized_confidence,
            is_malicious=score >= MALICIOUS_SCORE_THRESHOLD, is_failure=False,
        ))
    return out


def collect_signals(case):
    reports, scores, confidences = [], [], []
    signals = []
    failures = 0

    if case.fileOrMail:
        file = getattr(case.fileOrMail, "file", None)
        if file:
            off = len(scores)
            failures += process_file_ioc(file, reports, scores, confidences, 0, case.id)
            signals += _signals_from(scores, confidences, off, "file")

        mail = getattr(case.fileOrMail, "mail", None)
        if mail:
            off = len(scores)
            # Default ON: only an explicitly stored False keeps embedded IOCs
            # voting here. get_config returns None (not the default arg) for an
            # unset key once the cache is warm, so compare against False directly.
            score_artifacts = get_config("scoring.mail_embedded_categorical") is False
            failures += process_mail(mail, reports, scores, confidences, 0, case.id,
                                     score_artifacts=score_artifacts)
            signals += _signals_from(scores, confidences, off, "mail")

    if case.nonFileIocs:
        ioc_data = case.nonFileIocs.get_iocs()
        for ioc_type in ("url", "ip", "hash", "domain"):
            ioc = ioc_data.get(ioc_type)
            if ioc:
                off = len(scores)
                failures += process_ioc(ioc, ioc_type, reports, scores, confidences, 0)
                signals += _signals_from(scores, confidences, off, ioc_type)

    # NB: ObservableGroup (IOC-road) cases never reach here — get_report()
    # branches to finalise_ioc_group() before collect_signals() is called.
    # The categorical engine (score_observable) owns that road; running the
    # weighted process_ioc here would double-score the shared observable rows.

    signals += [Signal("failed", 0, 0, False, True) for _ in range(failures)]
    ai_missing = (case.results_ai == Result.INCONCLUSIVE)

    ai = None
    if case.confidence_ai and not ai_missing:
        ai = AiSignal(score=case.score_ai or 0, confidence=min(round(case.confidence_ai or 0), 100))

    deny_listed, deny_reason = _compute_deny_listed(case)
    return signals, ai, deny_listed, ai_missing, deny_reason


def _compute_deny_listed(case) -> tuple[bool, str]:
    deny = get_deny_listed_domains_set()
    if case.fileOrMail and case.fileOrMail.mail:
        found, reason = _check_mail_artifacts_for_deny_list(case.fileOrMail.mail, deny, logger)
        if found:
            return True, reason
    if case.nonFileIocs and getattr(case.nonFileIocs, "url", None):
        address = case.nonFileIocs.url.address
        if _is_address_deny_listed(address, deny, logger):
            return True, f"URL deny-listed: {address}"
    return False, ""


def _report_target(r):
    """(data, kind) the allow-list is checked against, or None for targets it never covers."""
    if r.url_id:
        return r.url.address, "url"
    if r.domain_id:
        return r.domain.value, "domain"
    if r.ip_id:
        return r.ip.address, "ip"
    if r.file_id:
        return r.file.file_path, "file"
    return None


def _marker_still_valid(r) -> bool:
    """Re-run the allow-list check for the report's target: a marker stored in
    category lapses when the entry was removed or the domain is now overridden."""
    from score_process.scoring.cortex_analyzers.allow_list import check_allow_list

    target = _report_target(r)
    return bool(target) and any(check_allow_list(*target).model_dump().values())


def reapply_allow_list(reports) -> int:
    """Rewrite stored reports to the current allow-list. A report scored before its
    target was listed is set to safe/0/100 and its original result kept in
    `pre_allowlist`; one whose listing has since lapsed gets the original back.
    Returns how many reports changed."""
    from score_process.scoring.cortex_analyzers.allow_list import check_allow_list, is_allow_listed_category

    changed = 0
    for r in reports:
        if r.status != "Success":
            continue
        target = _report_target(r)
        if target is None:
            continue
        marker = next((v for v in check_allow_list(*target).model_dump().values() if v), None)
        marked = is_allow_listed_category(r.category)
        if marker and not marked:
            r.pre_allowlist = {"level": r.level, "score": r.score,
                               "confidence": r.confidence, "category": r.category}
            r.level, r.score, r.confidence, r.category = "safe", 0, 100, marker
        elif not marker and marked and r.pre_allowlist:
            old = r.pre_allowlist
            r.level, r.score, r.confidence, r.category = (
                old["level"], old["score"], old["confidence"], old["category"])
            r.pre_allowlist = None
        else:
            continue
        r.save(update_fields=["level", "score", "confidence", "category", "pre_allowlist"])
        changed += 1
    return changed


def collect_votes(case, ai=None) -> tuple:
    """One Vote per analyzer from the case's latest reports plus the AI signal.
    An analyzer's band is the worst across its reports, so a tool that flags one
    artifact and is allow-listed on another votes dissent, not safe."""
    from api.utils.analyzer_reports import reports_for_case
    from api.views.investigations import _dedup_analyzer_reports
    from cortex_job.cortex_utils.cortex_and_job_management import _get_cortex_config
    from cortex_job.models import Analyzer
    from score_process.scoring.cortex_analyzers.allow_list import is_allow_listed_category

    ai_name = _get_cortex_config().get("analyzers", {}).get("ai")
    seen: dict = {}   # analyzer name -> [weight, worst band, any allow-list hit, any non-Safe report on an unlisted target]

    def add(name, weight, report_band, hit, unlisted=False):
        cur = seen.setdefault(name, [weight, Result.SAFE, False, False])
        if _BAND_RANK[report_band] > _BAND_RANK[cur[1]]:
            cur[1] = report_band
        cur[2] = cur[2] or hit
        cur[3] = cur[3] or unlisted

    for r in _dedup_analyzer_reports(reports_for_case(case, defer_full=True)):
        if (r.status != "Success" or r.level == "info" or r.confidence < CONF_FLOOR
                or r.analyzer.name == ai_name):
            continue
        report_band = band(r.score)
        flagged = report_band != Result.SAFE
        add(r.analyzer.name, r.analyzer.weight, report_band,
            is_allow_listed_category(r.category) and _marker_still_valid(r),
            unlisted=flagged and not _marker_still_valid(r))

    if ai is not None and ai_name and ai.confidence >= CONF_FLOOR:
        weight = Analyzer.objects.filter(name=ai_name).values_list("weight", flat=True).first()
        if weight:
            from score_process.scoring import trusted_sender

            ai_band = band(ai.score)
            flagged = ai_band != Result.SAFE
            # The AI reads the mail text, which no allow-list covers: only a provably company-authored
            # mail with nothing but trusted links lets an allow-list overrule it.
            overridable = flagged and trusted_sender.ai_may_be_overruled(case)
            add(ai_name, weight, ai_band, False, unlisted=flagged and not overridable)

    return tuple(Vote(n, w, b, hit and b == Result.SAFE, dissent_on_listed=b != Result.SAFE and not unl)
                 for n, (w, b, hit, unl) in seen.items() if w > 0)
