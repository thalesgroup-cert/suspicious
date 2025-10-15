import logging
from typing import Any, Dict, Tuple, Optional # Import necessary typing modules
from enum import Enum # Added for potential use in update_mail_part_with_scores

# Assuming get_score_level is importable from the correct location
from score_process.scoring.case_score_calculation import get_score_level
# --- Constants ---
MALICIOUS_LEVEL_NAME: str = "malicious"
MALICIOUS_SCORE: int = 10
MALICIOUS_CONFIDENCE: int = 100


# --- Loggers ---
# It's conventional to get loggers at the module level
# Keep your original logger names if they are standard in your project
script_logger = logging.getLogger(__name__) # General logger for this script module
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs') # Specific logger


# --- Core Update Function ---
def update_scores(
    obj: Any, # Use Any or a specific Protocol/Base Class if available
    level_attr: str,
    score_attr: str,
    confidence_attr: str,
    is_malicious: bool
) -> bool:
    """
    Update score, level, and confidence attributes of an object.

    Sets predefined values if malicious, otherwise calculates the level
    based on the *existing* score attribute. Assumes score/confidence
    are already set correctly in the non-malicious case before calling this.

    Args:
        obj: The object to update (must have specified attributes and a .save() method).
        level_attr: The attribute name for the score level (e.g., 'ioc_level').
        score_attr: The attribute name for the score (e.g., 'ioc_score').
        confidence_attr: The attribute name for the confidence (e.g., 'ioc_confidence').
        is_malicious: True if the object is considered malicious.

    Returns:
        bool: True if the update and save were successful, False otherwise.
    """
    try:
        if is_malicious:
            update_cases_logger.debug("Object identified as malicious. Setting attributes on %r.", obj)
            setattr(obj, level_attr, MALICIOUS_LEVEL_NAME)
            setattr(obj, score_attr, MALICIOUS_SCORE)
            setattr(obj, confidence_attr, MALICIOUS_CONFIDENCE)
            update_cases_logger.debug(
                "Set malicious attributes: %s=%s, %s=%s, %s=%s",
                level_attr, MALICIOUS_LEVEL_NAME,
                score_attr, MALICIOUS_SCORE,
                confidence_attr, MALICIOUS_CONFIDENCE
            )
        else:
            update_cases_logger.debug("Object not malicious. Updating level based on existing score for %r.", obj)
            current_score = getattr(obj, score_attr)
            # Ensure score is int if get_score_level expects int
            if not isinstance(current_score, int):
                try:
                    current_score = int(round(current_score)) # Or handle float scores if needed
                except (ValueError, TypeError):
                    update_cases_logger.error(
                        "Cannot determine level: score attribute '%s' on %r has non-numeric value %r.",
                        score_attr, obj, getattr(obj, score_attr)
                    )
                    return False # Cannot proceed

            try:
                # Calculate level based on current score
                calculated_level = get_score_level(current_score)
                setattr(obj, level_attr, calculated_level)
                update_cases_logger.debug(
                    "Set non-malicious level: %s=%s (derived from %s=%s)",
                    level_attr, calculated_level, score_attr, current_score
                )
            except ValueError as e:
                # Handle case where score is out of range for get_score_level
                update_cases_logger.warning(
                    "Could not determine level for score %s on %r using attribute '%s': %s",
                    current_score, obj, score_attr, e
                )
                # Decide if you should proceed to save or return False
                # For now, we log a warning and proceed to save potentially unchanged obj.
                # Alternatively, set a default level or return False:
                # setattr(obj, level_attr, "unknown") # Example default
                # return False

        # Save the object
        obj.save()
        update_cases_logger.debug("Object %r saved successfully.", obj)
        return True

    except AttributeError as e:
        update_cases_logger.error("Attribute error updating scores for %r: %s", obj, e)
        return False
    except Exception as e:
        # Catch other potential errors during save or processing
        update_cases_logger.exception("Unexpected error updating scores for %r: %s", obj, e)
        return False


# --- Wrapper Functions ---

def update_artifact_with_scores(artifact: Any, is_malicious: bool) -> bool:
    """
    Update an artifact with scores based on its malicious status.

    Args:
        artifact: The artifact object to be updated.
        is_malicious: True if the artifact is considered malicious.

    Returns:
        bool: True if the update and save were successful, False otherwise.
    """
    update_cases_logger.info("Updating scores for artifact %r (malicious=%s)", artifact, is_malicious)
    return update_scores(artifact, 'ioc_level', 'ioc_score', 'ioc_confidence', is_malicious)


# Corrected type hint and parameter name
def update_file_with_scores(file_obj: Any, is_malicious: bool) -> bool:
    """
    Update a file object with scores based on its malicious status.

    Args:
    file_obj: The file object (not path) to update scores for.
    Must have 'file_level', 'file_score', 'file_confidence' attributes
    and a .save() method.
    is_malicious: True if the file is considered malicious.

    Returns:
    bool: True if the update and save were successful, False otherwise.
    """
    update_cases_logger.info("Updating scores for file object %r (malicious=%s)", file_obj, is_malicious)
    return update_scores(file_obj, 'file_level', 'file_score', 'file_confidence', is_malicious)


# Optional: Define an Enum for mail part types
class MailPartType(Enum):
    BODY = "mail_body"
    HEADER = "mail_header"

    @classmethod
    def get_attributes(cls, part_type) -> Optional[Tuple[str, str, str]]:
        """ Helper to get attribute names based on Enum member """
        _attribute_map: Dict[MailPartType, Tuple[str, str, str]] = {
            MailPartType.BODY: ('body_level', 'body_score', 'body_confidence'),
            MailPartType.HEADER: ('header_level', 'header_score', 'header_confidence'),
        }
        return _attribute_map.get(part_type)


def update_mail_part_with_scores(
    mail_part: Any,
    part_type: str,
    is_malicious: bool
) -> bool:
    """
    Update a mail part object with scores based on its type and malicious status.

    Args:
        mail_part: The mail part object to update scores for.
        part_type: The type of the mail part (MailPartType.BODY or MailPartType.HEADER).
        is_malicious: True if the mail part is considered malicious.

    Returns:
        bool: True if the update and save were successful, False otherwise.
    """
    update_cases_logger.info(
        "Updating scores for mail part %r (type=%s, malicious=%s)",
        mail_part, part_type, is_malicious
    )

    attributes = MailPartType.get_attributes(part_type)

    if attributes:
        level_attr, score_attr, confidence_attr = attributes
        return update_scores(mail_part, level_attr, score_attr, confidence_attr, is_malicious)
    else:
        # This case should be less likely if using the Enum correctly
        update_cases_logger.warning(
            "Cannot update mail part %r: unknown type enum member %s.", mail_part, part_type
        )
        return False