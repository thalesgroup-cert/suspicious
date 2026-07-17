"""
Score update helpers for case artifacts.
"""
import logging
from enum import Enum
from typing import Any, Dict, Optional, Tuple, Union

from score_process.scoring.case_score_calculation import get_score_level

# ── Constants ────────────────────────────────────────────────────────────────
MALICIOUS_LEVEL_NAME: str = "malicious"
MALICIOUS_SCORE: int      = 10
MALICIOUS_CONFIDENCE: int = 100

# ── Loggers ───────────────────────────────────────────────────────────────────
script_logger       = logging.getLogger(__name__)
update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


# ── Core update ───────────────────────────────────────────────────────────────

def update_scores(
    obj: Any,
    level_attr: str,
    score_attr: str,
    confidence_attr: str,
    is_malicious: bool,
) -> bool:
    """
    Write level, score, and confidence onto *obj* then call obj.save().

    Uses update_fields so only the three scoring columns are touched —
    prevents race-condition overwrites on unrelated fields that a concurrent
    request may have changed between the SELECT and this PATCH.

    Returns True on success, False on any error.
    """
    try:
        if is_malicious:
            setattr(obj, level_attr,      MALICIOUS_LEVEL_NAME)
            setattr(obj, score_attr,      MALICIOUS_SCORE)
            setattr(obj, confidence_attr, MALICIOUS_CONFIDENCE)
            update_cases_logger.debug(
                "Malicious attrs set on %r: %s=%s, %s=%s, %s=%s",
                obj,
                level_attr,      MALICIOUS_LEVEL_NAME,
                score_attr,      MALICIOUS_SCORE,
                confidence_attr, MALICIOUS_CONFIDENCE,
            )
        else:
            raw_score = getattr(obj, score_attr)
            try:
                current_score = round(raw_score)
            except (TypeError, ValueError):
                update_cases_logger.error(
                    "Non-numeric score attribute %r=%r on %r — cannot set level.",
                    score_attr, raw_score, obj,
                )
                return False

            try:
                calculated_level = get_score_level(current_score)
            except ValueError as exc:
                update_cases_logger.warning(
                    "Score %s on %r out of range for level calculation: %s",
                    current_score, obj, exc,
                )
            else:
                setattr(obj, level_attr, calculated_level)
                update_cases_logger.debug(
                    "Non-malicious level set on %r: %s=%s (from %s=%s)",
                    obj, level_attr, calculated_level, score_attr, current_score,
                )

        obj.save(update_fields=[level_attr, score_attr, confidence_attr])
        update_cases_logger.debug("Saved %r (update_fields=%s/%s/%s).", obj, level_attr, score_attr, confidence_attr)
        return True

    except AttributeError as exc:
        update_cases_logger.error("AttributeError updating scores on %r: %s", obj, exc)
        return False
    except Exception as exc:
        update_cases_logger.exception("Unexpected error updating scores on %r: %s", obj, exc)
        return False


# ── Wrappers ──────────────────────────────────────────────────────────────────

def update_artifact_with_scores(artifact: Any, is_malicious: bool) -> bool:
    update_cases_logger.info("Updating artifact %r (malicious=%s).", artifact, is_malicious)
    return update_scores(artifact, "ioc_level", "ioc_score", "ioc_confidence", is_malicious)


def update_file_with_scores(file_obj: Any, is_malicious: bool) -> bool:
    update_cases_logger.info("Updating file %r (malicious=%s).", file_obj, is_malicious)
    return update_scores(file_obj, "file_level", "file_score", "file_confidence", is_malicious)


# ── Mail part helpers ─────────────────────────────────────────────────────────

class MailPartType(Enum):
    BODY   = "mail_body"
    HEADER = "mail_header"

    @classmethod
    def get_attributes(
        cls,
        part_type: Union["MailPartType", str],
    ) -> Optional[Tuple[str, str, str]]:
        """
        Return (level_attr, score_attr, confidence_attr) for a given part type.

        Accepts either a MailPartType enum member or the plain string value
        ("mail_body" / "mail_header") so callers that only have the string
        do not need to import this enum.
        """
        _map: Dict["MailPartType", Tuple[str, str, str]] = {
            cls.BODY:   ("body_level",   "body_score",   "body_confidence"),
            cls.HEADER: ("header_level", "header_score", "header_confidence"),
        }
        if isinstance(part_type, cls):
            return _map.get(part_type)
        try:
            member = next(m for m in cls if m.value == part_type)
            return _map.get(member)
        except StopIteration:
            return None


def update_mail_part_with_scores(
    mail_part: Any,
    part_type: Union[MailPartType, str],
    is_malicious: bool,
) -> bool:
    """
    Update a mail part (body or header) with scoring results.

    part_type may be a MailPartType enum member or a plain string
    ("mail_body" / "mail_header").
    """
    update_cases_logger.info(
        "Updating mail part %r (type=%s, malicious=%s).", mail_part, part_type, is_malicious
    )
    attributes = MailPartType.get_attributes(part_type)
    if attributes is None:
        update_cases_logger.warning(
            "Cannot update mail part %r: unknown type %r.", mail_part, part_type
        )
        return False
    level_attr, score_attr, confidence_attr = attributes
    return update_scores(mail_part, level_attr, score_attr, confidence_attr, is_malicious)