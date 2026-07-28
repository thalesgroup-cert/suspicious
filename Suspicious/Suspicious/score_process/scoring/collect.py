"""Read the DB and build the typed inputs the pure engine consumes.

Reuses the existing per-artifact processing (which still persists analyzer
reports and artifact scores) but converts its parallel score/confidence output
into Signal objects, plus the AI signal and the deny-list flag.
"""
import logging

from score_process.scoring.engine import Signal, AiSignal, MALICIOUS_SCORE_THRESHOLD
from score_process.scoring.processing import (
    process_file_ioc, process_mail, process_ioc,
)
from score_process.scoring.case_score_calculation import (
    get_deny_listed_domains_set,
    _check_mail_artifacts_for_deny_list,
    _is_address_deny_listed,
)
from case_handler.models import Result

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def _signals_from(scores, confidences, offset, source):
    """Turn the new (score, confidence) pairs appended since `offset` into
    Signals. is_malicious is the per-artifact equivalent of the old per-report
    vote — score-only by design, so the malicious-vote override in score_case
    can fire on a high-score artifact regardless of its confidence."""
    out = []
    for score, conf in zip(scores[offset:], confidences[offset:]):
        normalized_confidence = min(round(conf / 10), 100)
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
            failures += process_mail(mail, reports, scores, confidences, 0, case.id)
            signals += _signals_from(scores, confidences, off, "mail")

    if case.nonFileIocs:
        ioc_data = case.nonFileIocs.get_iocs()
        for ioc_type in ("url", "ip", "hash", "domain"):
            ioc = ioc_data.get(ioc_type)
            if ioc:
                off = len(scores)
                failures += process_ioc(ioc, ioc_type, reports, scores, confidences, 0)
                signals += _signals_from(scores, confidences, off, ioc_type)

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
