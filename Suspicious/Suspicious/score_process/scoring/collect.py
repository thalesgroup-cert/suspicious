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
    seen: dict = {}   # analyzer name -> [weight, worst band, any allow-list hit]

    def add(name, weight, report_band, hit):
        cur = seen.setdefault(name, [weight, Result.SAFE, False])
        if _BAND_RANK[report_band] > _BAND_RANK[cur[1]]:
            cur[1] = report_band
        cur[2] = cur[2] or hit

    for r in _dedup_analyzer_reports(reports_for_case(case, defer_full=True)):
        if (r.status != "Success" or r.level == "info" or r.confidence < CONF_FLOOR
                or r.analyzer.name == ai_name):
            continue
        add(r.analyzer.name, r.analyzer.weight, band(r.score), is_allow_listed_category(r.category))

    if ai is not None and ai_name and ai.confidence >= CONF_FLOOR:
        weight = Analyzer.objects.filter(name=ai_name).values_list("weight", flat=True).first()
        if weight:
            add(ai_name, weight, band(ai.score), False)

    return tuple(Vote(n, w, b, hit and b == Result.SAFE) for n, (w, b, hit) in seen.items() if w > 0)
