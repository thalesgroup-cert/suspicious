import logging
from enum import Enum
from typing import List, Set, Optional, Type, Union

from urllib.parse import urlparse
from email.utils import parseaddr

# Models
from settings.models import DenyListDomain, CampaignDomainAllowList
from domain_process.models import Domain
from url_process.models import URL
from email_process.models import MailAddress

# --- Constants ---

# Artifact
ARTIFACT_DENY_LIST_SCORE = 10
ARTIFACT_DENY_LIST_CONFIDENCE = 100

# IOC
IOC_DENY_LIST_SCORE = 10
IOC_DENY_LIST_CONFIDENCE = 100
IOC_DENY_LIST_LEVEL = "critical"

# Case
DEFAULT_SCORE = 5
DEFAULT_CONFIDENCE = 0
DENY_LIST_SCORE = 10
DENY_LIST_CONFIDENCE = 100
MAX_FINAL_SCORE = 10
MAX_FINAL_CONFIDENCE = 100

# Adjustment thresholds
HIGH_SCORE_THRESHOLD = 8
MAIL_HEADER_HIGH_THRESHOLD = 8
HIGH_SCORE_COUNT_THRESHOLD_1 = 3
HIGH_SCORE_COUNT_THRESHOLD_2 = 2
ADJUSTED_SCORE_FLOOR = 7

# Logging
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')
logger = logging.getLogger(__name__)

# --- Enums ---

class ScoreLevel(Enum):
    MALICIOUS = (8, 10)
    SUSPICIOUS = (6, 7)
    INFO = (5, 5)
    SAFE = (0, 4)

class ResultRange(Enum):
    DANGEROUS = (8, 10)
    SUSPICIOUS = (5, 7)
    SAFE = (0, 4)

# --- Helpers ---

def _find_category_in_enum_range(
    score: Union[int, float],
    enum_class: Type[Enum],
    category_type_name: str = "category",
    capitalize_result: bool = False,
    logger: Optional[logging.Logger] = None
) -> str:
    """
    Return the name of the enum member whose (start, end) range contains the score.
    """
    for member in enum_class:
        try:
            if not isinstance(member.value, (tuple, list)) or len(member.value) < 2:
                raise ValueError
            start, end = member.value[:2]
            if not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
                raise TypeError
        except (ValueError, TypeError, IndexError) as e:
            msg = f"Invalid enum value for {member.name}: {member.value}. {e}"
            if logger:
                logger.error(msg)
            raise TypeError(msg)

        if start <= score <= end:
            if logger:
                logger.info(f"Score {score} -> {category_type_name.capitalize()}: {member.name}")
            return member.name.capitalize() if capitalize_result else member.name

    msg = f"{category_type_name.capitalize()} for score {score} not found in {enum_class.__name__}."
    if logger:
        logger.warning(msg)
    raise ValueError(msg)

def get_deny_listed_domains_set() -> Set[str]:
    """
    Return a set of deny_listed domains from the DB and Campain domains.
    """
    domains = set(
        DenyListDomain.objects.filter(domain__value__isnull=False)
        .values_list('domain__value', flat=True)
    ) | set(
        CampaignDomainAllowList.objects.filter(domain__value__isnull=False)
        .values_list('domain__value', flat=True)
    )
    update_cases_logger.info("Fetched %d deny_listed domains.", len(domains))
    return domains

def _extract_domain_from_url(url_string: str, logger: logging.Logger) -> Optional[str]:
    try:
        return urlparse(url_string).hostname
    except Exception as e:
        logger.error(f"Failed to parse URL '{url_string}': {e}")
        return None

def _extract_domain_from_email_address(
    address: str,
    logger: logging.Logger,
) -> Optional[str]:
    try:
        _, email_addr = parseaddr(address)
        if "@" not in email_addr:
            return None
        return email_addr.rsplit("@", 1)[1].lower()
    except Exception as e:
        logger.error(f"Failed to parse email address '{address}': {e}")
        return None

def _update_ioc(obj, logger, label: str):
    for field in ["ioc_score", "ioc_confidence", "ioc_level"]:
        if not hasattr(obj, field):
            logger.warning(f"{label} missing field '{field}'")
            return
    obj.ioc_score = IOC_DENY_LIST_SCORE
    obj.ioc_confidence = IOC_DENY_LIST_CONFIDENCE
    obj.ioc_level = IOC_DENY_LIST_LEVEL
    try:
        obj.save()
        logger.info(f"Updated {label} IOC: {getattr(obj, 'address', obj)}")
    except Exception as e:
        logger.exception(f"Error saving {label} IOC: {e}")

def _update_ioc_scores_for_deny_listed_domain(
    domain: Domain,
    logger: logging.Logger,
    originating_url: Optional[URL] = None,
    originating_mail: Optional[MailAddress] = None
):
    _update_ioc(domain, logger, f"Domain '{domain.value}'")
    for url in domain.linked_urls.exclude(id=originating_url.id if originating_url else None):
        _update_ioc(url, logger, f"Linked URL '{url.address}'")
    for mail in domain.linked_mail_addresses.exclude(id=originating_mail.id if originating_mail else None):
        _update_ioc(mail, logger, f"Linked MailAddress '{mail.address}'")

def _is_address_deny_listed(address: str, deny_list: Set[str], logger: logging.Logger) -> bool:
    if address in deny_list:
        return True
    parts = address.split('.')
    for i in range(len(parts) - 1):
        subdomain = '.'.join(parts[i:])
        if subdomain in deny_list:
            logger.debug(f"'{address}' matched '{subdomain}' in deny_list")
            return True
    return False

def _check_mail_artifacts_for_deny_list(mail, deny_list: Set[str], logger: logging.Logger) -> bool:
    try:
        artifacts = getattr(mail, 'mail_artifacts', []).all()
    except Exception as e:
        logger.error(f"Error accessing mail artifacts: {e}")
        return False

    for artifact in artifacts:
        domain_obj, url_obj, address = None, None, None
        source = "Unknown"

        if hasattr(artifact, 'artifactIsMailAddress') and artifact.artifactIsMailAddress:
            mail_address = getattr(artifact.artifactIsMailAddress, 'mail_address', None)
            if mail_address and hasattr(mail_address, 'address'):
                address = _extract_domain_from_email_address(mail_address.address, logger)
                source = "Mail Address"

        if hasattr(artifact, 'artifactIsDomain') and artifact.artifactIsDomain:
            domain = getattr(artifact.artifactIsDomain, 'domain', None)
            if domain and hasattr(domain, 'value'):
                domain_obj, address, source = domain, domain.value, "Domain"

        elif hasattr(artifact, 'artifactIsUrl') and artifact.artifactIsUrl:
            url = getattr(artifact.artifactIsUrl, 'url', None)
            if url and hasattr(url, 'address'):
                address = _extract_domain_from_url(url.address, logger)
                if address:
                    url_obj, source = url, "URL"

        if not address or not _is_address_deny_listed(address, deny_list, logger):
            continue

        logger.info(f"DenyListed {source} found: {address} (Artifact ID: {getattr(artifact, 'id', 'N/A')})")

        if all(hasattr(artifact, attr) for attr in ["artifact_score", "artifact_confidence"]):
            artifact.artifact_score = ARTIFACT_DENY_LIST_SCORE
            artifact.artifact_confidence = ARTIFACT_DENY_LIST_CONFIDENCE
            try:
                artifact.save()
                logger.info(f"Updated artifact {getattr(artifact, 'id', 'N/A')}")
            except Exception as e:
                logger.exception(f"Error saving artifact {getattr(artifact, 'id', 'N/A')}: {e}")

        domain_target = domain_obj if source == "Domain" else Domain.objects.filter(value=address).first()
        if url_obj:
            _update_ioc(url_obj, logger, f"URL '{url_obj.address}'")
        if domain_target:
            _update_ioc_scores_for_deny_listed_domain(domain_target, logger, originating_url=url_obj)
        else:
            logger.info(f"No Domain object found for '{address}'")

        return True

    return False

def _calculate_and_set_final_scores(
    case: "Case",
    total_scores: List[float],
    total_confidences: List[float],
    logger: logging.Logger,
    mail_header_score: Optional[float] = None
):
    if not total_scores:
        logger.info("No scores available, defaulting to 0.")
        case.finalScore = DEFAULT_SCORE
        case.finalConfidence = DEFAULT_CONFIDENCE
        return

    avg_score = sum(total_scores) / len(total_scores)
    avg_confidence = sum(total_confidences) / len(total_confidences) if total_confidences else DEFAULT_CONFIDENCE

    logger.info("Average score: %f", avg_score)
    logger.info("Average confidence: %f", avg_confidence)

    if mail_header_score is not None:
        high_score_count = sum(1 for s in total_scores if s >= HIGH_SCORE_THRESHOLD)
        adjust = (
            (mail_header_score > MAIL_HEADER_HIGH_THRESHOLD and high_score_count >= HIGH_SCORE_COUNT_THRESHOLD_1)
            or
            (mail_header_score <= MAIL_HEADER_HIGH_THRESHOLD and high_score_count >= HIGH_SCORE_COUNT_THRESHOLD_2)
        )
        if adjust:
            logger.info("Adjusting score floor to %d", ADJUSTED_SCORE_FLOOR)
            avg_score = max(avg_score, ADJUSTED_SCORE_FLOOR)

    case.score = min(round(avg_score), MAX_FINAL_SCORE)
    case.confidence = min(round(avg_confidence), MAX_FINAL_CONFIDENCE)

    logger.info(" Processed total score: %d", case.score)
    logger.info("Processed total confidence: %d", case.confidence)
    
    logger.info("Checking if AI Conf is above final confidence")
    if case.confidenceAI > case.confidence:
        logger.info("AI Conf is above final confidence")
        case.finalScore = case.scoreAI
        case.finalConfidence = case.confidenceAI
    else:
        logger.info("AI Conf is not above final confidence")
        case.finalScore = case.score
        case.finalConfidence = case.confidence
    logger.info("Final score: %d", case.finalScore)
    logger.info("Final confidence: %d", case.finalConfidence)
    
# --- Public Interface ---

def calculate_final_scores(
    total_scores: List[float],
    total_confidences: List[float],
    case: "Case"
):
    logger = update_cases_logger
    logger.info("Calculating final scores")
    logger.info("Scores: %s", total_scores)
    logger.info("Confidences: %s", total_confidences)

    deny_listed_domains_set = get_deny_listed_domains_set()

    try:
        deny_listed = False
        mail_header_score = None

        if case.fileOrMail and case.fileOrMail.mail:
            mail = case.fileOrMail.mail
            mail_header_score = mail.mail_header.header_score
            if _check_mail_artifacts_for_deny_list(mail, deny_listed_domains_set, logger):
                case.finalScore = DENY_LIST_SCORE
                case.finalConfidence = DENY_LIST_CONFIDENCE
                deny_listed = True

        elif not deny_listed and case.nonFileIocs and case.nonFileIocs.url:
            url_address = case.nonFileIocs.url.address
            logger.info("Checking non-file IOC URL: %s", url_address)
            if _is_address_deny_listed(url_address, deny_listed_domains_set, logger):
                case.finalScore = DENY_LIST_SCORE
                case.finalConfidence = DENY_LIST_CONFIDENCE
                deny_listed = True

        if not deny_listed:
            _calculate_and_set_final_scores(case, total_scores, total_confidences, logger, mail_header_score)

    except Exception as e:
        logger.exception("Error calculating final scores: %s", e)
        # case.finalScore = -1
        # case.finalConfidence = -1

def calculate_result_ranges(final_score: float) -> str:
    """
    Return the result range (Safe/Suspicious/Dangerous) for the given score.
    """
    return _find_category_in_enum_range(
        score=final_score,
        enum_class=ResultRange,
        category_type_name="result range",
        capitalize_result=True,
        logger=update_cases_logger
    )

def get_score_level(score: int) -> str:
    """
    Return the score level (safe/info/suspicious/malicious) for the given score.
    """
    return _find_category_in_enum_range(
        score=score,
        enum_class=ScoreLevel,
        category_type_name="score level",
        capitalize_result=False,
        logger=update_cases_logger
    )
