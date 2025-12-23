from case_handler.models import Case
from django.db.models import Q
import logging

from case_handler.update_case.update_score_calculation import calculate_attachment_scores, calculate_artifact_scores, calculate_body_score, calculate_header_score, calculate_file_score, calculate_non_file_ioc_scores, calculate_total_scores, calculate_result_ranges, get_ioc_score
from score_process.score_utils.send_mail.service import MailNotificationService
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')

def update_linked_cases(object, type):
    """Update linked cases based on the given object and type.

    This function updates the linked cases in the database based on the provided object and type.
    It uses a type mapping dictionary to determine the appropriate query for each type.

    Args:
        object (Any): The object to update the linked cases for.
        type (str): The type of the object.

    Returns:
        Sends Mail to the reporter of the case.
    """
    
    type_mapping = {
        "file": Q(fileOrMail__file=object) | Q(fileOrMail__mail__mail_attachments__file=object),
        "ip": Q(fileOrMail__mail__mail_artifacts__artifactIsIp__ip=object) | Q(nonFileIocs__ip=object),
        "hash": Q(fileOrMail__mail__mail_artifacts__artifactIsHash__hash=object) | Q(nonFileIocs__hash=object) | Q(fileOrMail__file__linked_hash=object),
        "url": Q(fileOrMail__mail__mail_artifacts__artifactIsUrl__url=object) | Q(nonFileIocs__url=object),
        "body": Q(fileOrMail__mail__mail_body=object),
        "header": Q(fileOrMail__mail__mail_header=object),
    }

    linked_cases = Case.objects.filter(type_mapping.get(type, Q()))

    for case in linked_cases:
        old_results = case.results
        update_case_score(case)

        if old_results != case.results:
            cls = MailNotificationService.from_settings()
            cls.send_review_email(case)
            print(f"Case with id {case.id} has been updated from {old_results} to {case.results} with score {case.finalScore} and confidence {case.finalConfidence}")
        else:
            print(f"Case with id {case.id} has been updated with score {case.finalScore} and confidence {case.finalConfidence}")

def update_ioc_level_and_cases(obj, obj_type, level):
    """Update the IOC level and associated cases for the given object.

    Args:
        obj (object): The object to update (can be file or hash).
        obj_type (str): The type of the object ('file', 'body', 'header', 'hash', or other).
        level (int): The IOC level to set.

    Returns:
        object: The updated object.

    """
    ioc_score = get_ioc_score(level)
    ioc_confidence = 100
    level_upper = level.upper()

    if obj_type == 'file':
        obj.file_score = ioc_score
        obj.file_confidence = ioc_confidence
        obj.file_level = level_upper
        obj.save()

        # If the file has a linked hash, update it simultaneously
        if hasattr(obj, 'linked_hash') and obj.linked_hash:
            linked_hash = obj.linked_hash
            linked_hash.ioc_score = ioc_score
            linked_hash.ioc_confidence = ioc_confidence
            linked_hash.ioc_level = level_upper
            linked_hash.save()

    elif obj_type == 'body':
        obj.body_score = ioc_score
        obj.body_confidence = ioc_confidence
        obj.body_level = level_upper
        obj.save()

    elif obj_type == 'header':
        obj.header_score = ioc_score
        obj.header_confidence = ioc_confidence
        obj.header_level = level_upper
        obj.save()

    else:
        obj.ioc_score = ioc_score
        obj.ioc_confidence = ioc_confidence
        obj.ioc_level = level_upper
        obj.save()

    # Ensure cases linked to this object are updated
    update_linked_cases(obj, obj_type)
    
    return obj



def update_case_score(case):
    """Update the score and confidence of a case based on various factors.

    Args:
        case (Case): The case object to update.

    Raises:
        Exception: If an error occurs while updating the case score.
    """
    from .update_handler import get_attachments_and_artifacts
    try:
        update_cases_logger.info("Updating case score.")

        # Initialize lists for scores and confidences
        total_scores = []
        total_confidences = []

        if case.fileOrMail:
            # Calculate scores if there are attachments or artifacts
            attachments, artifacts = get_attachments_and_artifacts(case)

            # Check if there are any attachments and artifacts to calculate
            if attachments:
                attachment_scores, attachment_confidences = calculate_attachment_scores(attachments)
                total_scores.extend(attachment_scores)
                total_confidences.extend(attachment_confidences)
            
            if artifacts:
                artifact_scores, artifact_confidences = calculate_artifact_scores(artifacts)
                total_scores.extend(artifact_scores)
                total_confidences.extend(artifact_confidences)

            # Calculate body and header scores only if there's an associated mail
            if case.fileOrMail.mail:
                body_score, body_confidence = calculate_body_score(case)
                header_score, header_confidence = calculate_header_score(case)
                total_scores.extend([body_score])
                total_confidences.extend([body_confidence])
                total_scores.extend([header_score])
                total_confidences.extend([header_confidence])

            # Calculate file score only if there is an associated file
            if case.fileOrMail.file:
                file_score, file_confidence = calculate_file_score(case)
                update_cases_logger.info(f"File score: {file_score}, confidence: {file_confidence}")
                total_scores.append(file_score)
                total_confidences.append(file_confidence)

        # Handle non-file IoCs if they exist
        if case.nonFileIocs:
            non_file_ioc_score, non_file_ioc_confidence = calculate_non_file_ioc_scores(case)
            total_scores.append(non_file_ioc_score)
            total_confidences.append(non_file_ioc_confidence)
            update_cases_logger.info(f"Non-file IoC score: {non_file_ioc_score}, confidence: {non_file_ioc_confidence}")

        # Check if there are any scores to calculate
        if total_scores:
            avg_score = sum(total_scores) / len(total_scores)
            avg_confidence = sum(total_confidences) / len(total_confidences) if total_confidences else 0

            update_cases_logger.info(f"Average score: {avg_score}, Average confidence: {avg_confidence}")

            # Adjust based on logic from `calculate_final_scores`
            high_scores_count = sum(1 for score in total_scores if score >= 9)
            mail_header_score = header_score if case.fileOrMail and case.fileOrMail.mail else 0
            if (mail_header_score > 9 and high_scores_count >= 2) or (mail_header_score <= 9 and high_scores_count >= 1):
                avg_score = max(avg_score, 7)

            case.finalScore = min(round(avg_score), 10)
            update_cases_logger.info(f"Final score: {case.finalScore}")
            case.finalConfidence = min(round(avg_confidence), 100)
            update_cases_logger.info(f"Final confidence: {case.finalConfidence}")
        else:
            # Default to 0 if there are no scores
            update_cases_logger.info("No scores available, defaulting to 0.")
            case.finalScore = 0
            case.finalConfidence = 0

        # Update the results based on the final score
        case.results = calculate_result_ranges(case.finalScore)
        case.save()

        update_cases_logger.info(f"Case with id {case.id} updated with score {case.finalScore} and confidence {case.finalConfidence}")

    except Exception as e:
        update_cases_logger.error(f"Error occurred while updating case score: {str(e)}")
