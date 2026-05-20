# score_process/scoring/case_score_calculation.py
"""
Final score calculation and result range classification.
"""
import logging
from enum import Enum
from typing import TYPE_CHECKING, List, Optional, Set, Type, Union
from urllib.parse import urlparse
from email.utils import parseaddr

if TYPE_CHECKING:
    from case_handler.models import Case

from settings.models import CampaignDomainAllowList, DenyListDomain, WatcherMonitoredDomain
from domain_process.models import Domain
from email_process.models import MailAddress
from url_process.models import URL

# ── Constants ─────────────────────────────────────────────────────────────────
ARTIFACT_DENY_LIST_SCORE      = 10
ARTIFACT_DENY_LIST_CONFIDENCE = 100
IOC_DENY_LIST_SCORE           = 10
IOC_DENY_LIST_CONFIDENCE      = 100
IOC_DENY_LIST_LEVEL           = "critical"
DEFAULT_SCORE                 = 5
DEFAULT_CONFIDENCE            = 0
DENY_LIST_SCORE               = 10
DENY_LIST_CONFIDENCE          = 100
MAX_FINAL_SCORE               = 10
MAX_FINAL_CONFIDENCE          = 100
HIGH_SCORE_THRESHOLD          = 8
MAIL_HEADER_HIGH_THRESHOLD    = 8
HIGH_SCORE_COUNT_THRESHOLD_1  = 3
HIGH_SCORE_COUNT_THRESHOLD_2  = 2
ADJUSTED_SCORE_FLOOR          = 7

# ── Loggers ───────────────────────────────────────────────────────────────────
update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")
logger              = logging.getLogger(__name__)


# ── Score / result enums ──────────────────────────────────────────────────────
#
#  ScoreLevel   — used for individual analyzer outputs (ioc_level etc.)
#  ResultRange  — used for the case-level verdict (Safe / Suspicious / Dangerous)
#
#  Boundaries are INCLUSIVE and cover [0..10] without gaps or overlaps:
#
#  Score   0  1  2  3  4 | 5 | 6  7 | 8  9  10
#  Level  ──── SAFE ─────   I  ─SUS─  ─MALICIOUS─
#  Result ──── SAFE ─────   ───SUSP───  ─DANGEROUS─

class ScoreLevel(Enum):
    SAFE      = (0, 4)
    INFO      = (5, 5)
    SUSPICIOUS = (6, 7)
    MALICIOUS = (8, 10)


class ResultRange(Enum):
    SAFE       = (0, 4)
    SUSPICIOUS = (5, 7)
    DANGEROUS  = (8, 10)


# ── Generic range lookup ──────────────────────────────────────────────────────

def _find_category_in_enum_range(
    score: Union[int, float],
    enum_class: Type[Enum],
    category_type_name: str = "category",
    capitalize_result: bool = False,
    logger: Optional[logging.Logger] = None,
) -> str:
    for member in enum_class:
        try:
            start, end = member.value[:2]
        except (TypeError, ValueError, IndexError) as exc:
            msg = "Invalid enum value for %s: %s — %s" % (member.name, member.value, exc)
            if logger:
                logger.error(msg)
            raise TypeError(msg)

        if start <= score <= end:
            result = member.name.capitalize() if capitalize_result else member.name
            if logger:
                logger.info("Score %s → %s: %s", score, category_type_name, result)
            return result

    msg = "%s for score %s not found in %s." % (
        category_type_name.capitalize(), score, enum_class.__name__
    )
    if logger:
        logger.warning(msg)
    raise ValueError(msg)


# ── Public score helpers ──────────────────────────────────────────────────────

def get_score_level(score: int) -> str:
    return _find_category_in_enum_range(
        score=score,
        enum_class=ScoreLevel,
        category_type_name="score level",
        capitalize_result=False,
        logger=update_cases_logger,
    )


def calculate_result_ranges(final_score: float) -> str:
    return _find_category_in_enum_range(
        score=final_score,
        enum_class=ResultRange,
        category_type_name="result range",
        capitalize_result=True,
        logger=update_cases_logger,
    )


# ── Domain deny-list helpers ──────────────────────────────────────────────────

def get_deny_listed_domains_set() -> Set[str]:
    """
    Return the union of deny-listed, campaign, and watcher domains.
    Issues a single SQL UNION query instead of three separate queries.
    """
    qs = (
        DenyListDomain.objects
            .filter(domain__value__isnull=False)
            .values_list("domain__value", flat=True)
        .union(
            CampaignDomainAllowList.objects
                .filter(domain__value__isnull=False)
                .values_list("domain__value", flat=True)
        )
        .union(
            WatcherMonitoredDomain.objects
                .filter(domain__value__isnull=False)
                .values_list("domain__value", flat=True)
        )
    )
    domains = set(qs)
    update_cases_logger.info("Fetched %d deny-listed domains.", len(domains))
    return domains


def _extract_domain_from_url(url_string: str, _logger: logging.Logger) -> Optional[str]:
    try:
        return urlparse(url_string).hostname
    except Exception as exc:
        _logger.error("Failed to parse URL %r: %s", url_string, exc)
        return None


def _extract_domain_from_email_address(address: str, _logger: logging.Logger) -> Optional[str]:
    try:
        _, email_addr = parseaddr(address)
        if "@" not in email_addr:
            return None
        return email_addr.rsplit("@", 1)[1].lower()
    except Exception as exc:
        _logger.error("Failed to parse email address %r: %s", address, exc)
        return None


def _update_ioc(obj, _logger: logging.Logger, label: str) -> None:
    for field in ("ioc_score", "ioc_confidence", "ioc_level"):
        if not hasattr(obj, field):
            _logger.warning("%s missing field %r.", label, field)
            return
    obj.ioc_score      = IOC_DENY_LIST_SCORE
    obj.ioc_confidence = IOC_DENY_LIST_CONFIDENCE
    obj.ioc_level      = IOC_DENY_LIST_LEVEL
    try:
        obj.save(update_fields=["ioc_score", "ioc_confidence", "ioc_level"])
        _logger.info("Updated IOC for %s.", label)
    except Exception as exc:
        _logger.exception("Error saving IOC for %s: %s", label, exc)


def _update_ioc_scores_for_deny_listed_domain(
    domain: Domain,
    _logger: logging.Logger,
    originating_url: Optional[URL] = None,
    originating_mail: Optional[MailAddress] = None,
) -> None:
    _update_ioc(domain, _logger, "Domain '%s'" % domain.value)
    for url in domain.linked_urls.exclude(
        id=originating_url.id if originating_url else None
    ):
        _update_ioc(url, _logger, "Linked URL '%s'" % url.address)
    for mail in domain.linked_mail_addresses.exclude(
        id=originating_mail.id if originating_mail else None
    ):
        _update_ioc(mail, _logger, "Linked MailAddress '%s'" % mail.address)


def _is_address_deny_listed(address: str, deny_list: Set[str], _logger: logging.Logger) -> bool:
    if address in deny_list:
        return True
    parts = address.split(".")
    for i in range(len(parts) - 1):
        subdomain = ".".join(parts[i:])
        if subdomain in deny_list:
            _logger.debug("'%s' matched '%s' in deny_list.", address, subdomain)
            return True
    return False


def _check_mail_artifacts_for_deny_list(
    mail, deny_list: Set[str], _logger: logging.Logger
) -> bool:
    """
    Scan ALL mail artifacts for deny-listed domains.

    Returns True if at least one was found. Previously the function
    returned on the first match, leaving subsequent deny-listed artifacts
    unscored.
    """
    try:
        artifacts = getattr(mail, "mail_artifacts", None)
        if artifacts is None:
            return False
        artifacts = artifacts.all()
    except Exception as exc:
        _logger.error("Error accessing mail artifacts: %s", exc)
        return False

    found_any = False

    for artifact in artifacts:
        domain_obj, url_obj, address, source = None, None, None, "Unknown"

        if getattr(artifact, "artifactIsMailAddress", None):
            mail_address = getattr(artifact.artifactIsMailAddress, "mail_address", None)
            if mail_address and hasattr(mail_address, "address"):
                address = _extract_domain_from_email_address(mail_address.address, _logger)
                source = "Mail Address"

        if getattr(artifact, "artifactIsDomain", None):
            domain = getattr(artifact.artifactIsDomain, "domain", None)
            if domain and hasattr(domain, "value"):
                domain_obj, address, source = domain, domain.value, "Domain"

        elif getattr(artifact, "artifactIsUrl", None):
            url = getattr(artifact.artifactIsUrl, "url", None)
            if url and hasattr(url, "address"):
                address = _extract_domain_from_url(url.address, _logger)
                if address:
                    url_obj, source = url, "URL"

        if not address or not _is_address_deny_listed(address, deny_list, _logger):
            continue

        _logger.info(
            "Deny-listed %s found: %s (artifact id=%s).",
            source, address, getattr(artifact, "id", "N/A"),
        )

        if hasattr(artifact, "artifact_score") and hasattr(artifact, "artifact_confidence"):
            artifact.artifact_score      = ARTIFACT_DENY_LIST_SCORE
            artifact.artifact_confidence = ARTIFACT_DENY_LIST_CONFIDENCE
            try:
                artifact.save(update_fields=["artifact_score", "artifact_confidence"])
            except Exception as exc:
                _logger.exception("Error saving artifact %s: %s", getattr(artifact, "id", "N/A"), exc)

        domain_target = domain_obj or Domain.objects.filter(value=address).first()
        if url_obj:
            _update_ioc(url_obj, _logger, "URL '%s'" % url_obj.address)
        if domain_target:
            _update_ioc_scores_for_deny_listed_domain(
                domain_target, _logger, originating_url=url_obj
            )
        else:
            _logger.info("No Domain object found for %r.", address)

        found_any = True

    return found_any


# ── Final score calculation ───────────────────────────────────────────────────

def _calculate_and_set_final_scores(
    case: "Case",
    total_scores: List[float],
    total_confidences: List[float],
    _logger: logging.Logger,
    mail_header_score: Optional[float] = None,
) -> None:
    if not total_scores:
        _logger.info("No scores available — defaulting to %s/%s.", DEFAULT_SCORE, DEFAULT_CONFIDENCE)
        case.final_score      = DEFAULT_SCORE
        case.final_confidence = DEFAULT_CONFIDENCE
        return

    avg_score      = sum(total_scores)      / len(total_scores)
    avg_confidence = sum(total_confidences) / len(total_confidences) if total_confidences else DEFAULT_CONFIDENCE

    _logger.info("Average score=%s confidence=%s.", avg_score, avg_confidence)

    if mail_header_score is not None:
        high_score_count = sum(1 for s in total_scores if s >= HIGH_SCORE_THRESHOLD)
        adjust = (
            (mail_header_score >  MAIL_HEADER_HIGH_THRESHOLD and high_score_count >= HIGH_SCORE_COUNT_THRESHOLD_1)
            or
            (mail_header_score <= MAIL_HEADER_HIGH_THRESHOLD and high_score_count >= HIGH_SCORE_COUNT_THRESHOLD_2)
        )
        if adjust:
            _logger.info("Raising score floor to %s.", ADJUSTED_SCORE_FLOOR)
            avg_score = max(avg_score, ADJUSTED_SCORE_FLOOR)

    case.score      = min(round(avg_score),      MAX_FINAL_SCORE)
    case.confidence = min(round(avg_confidence), MAX_FINAL_CONFIDENCE)
    _logger.info("Processed score=%s confidence=%s.", case.score, case.confidence)

    # Use AI scores when they carry higher confidence
    if case.confidence_ai > case.confidence:
        _logger.info("AI confidence (%s) > human confidence (%s) — using AI scores.", case.confidence_ai, case.confidence)
        case.final_score      = case.score_ai
        case.final_confidence = case.confidence_ai
    else:
        case.final_score      = case.score
        case.final_confidence = case.confidence

    _logger.info("Final score=%s confidence=%s.", case.final_score, case.final_confidence)

    # Persist — this was previously missing; values were computed in memory only.
    case.save(update_fields=["score", "confidence", "final_score", "final_confidence"])


def calculate_final_scores(
    total_scores: List[float],
    total_confidences: List[float],
    case: "Case",
) -> None:
    _logger = update_cases_logger
    _logger.info("Calculating final scores — scores=%s confidences=%s.", total_scores, total_confidences)

    deny_listed_domains_set = get_deny_listed_domains_set()

    try:
        deny_listed        = False
        mail_header_score  = None

        if case.fileOrMail and case.fileOrMail.mail:
            mail = case.fileOrMail.mail
            mail_header_score = getattr(getattr(mail, "mail_header", None), "header_score", None)

            if _check_mail_artifacts_for_deny_list(mail, deny_listed_domains_set, _logger):
                case.final_score      = DENY_LIST_SCORE
                case.final_confidence = DENY_LIST_CONFIDENCE
                deny_listed = True

        if not deny_listed and case.nonFileIocs and getattr(case.nonFileIocs, "url", None):
            url_address = case.nonFileIocs.url.address
            _logger.info("Checking non-file IOC URL: %s", url_address)
            if _is_address_deny_listed(url_address, deny_listed_domains_set, _logger):
                case.final_score      = DENY_LIST_SCORE
                case.final_confidence = DENY_LIST_CONFIDENCE
                deny_listed = True

        if not deny_listed:
            _calculate_and_set_final_scores(
                case, total_scores, total_confidences, _logger, mail_header_score
            )

    except Exception as exc:
        _logger.exception("Error calculating final scores: %s", exc)