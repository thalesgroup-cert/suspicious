import logging
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')

def calculate_attachment_scores(attachments):
    """Calculate the individual score and confidence for each attachment by averaging the file and linked hash scores.

    Args:
        attachments (list): A list of attachments.

    Returns:
        tuple: Two lists containing the individual scores and confidences.
    """
    scores = []
    confidences = []

    if not attachments:
        return scores, confidences  # Return empty lists if there are no attachments

    for attachment in attachments:
        file_score = attachment.file.file_score
        file_confidence = attachment.file.file_confidence
        ioc_score = attachment.file.linked_hash.ioc_score
        ioc_confidence = attachment.file.linked_hash.ioc_confidence

        # Average the file score and IOC score for this attachment
        avg_score = (file_score + ioc_score) / 2
        avg_confidence = (file_confidence + ioc_confidence) / 2

        # Add to lists of scores and confidences
        scores.append(avg_score)
        confidences.append(avg_confidence)

    # Return lists of scores and confidences
    return scores, confidences


def calculate_artifact_scores(artifacts):
    """Calculate the individual score and confidence for each artifact.

    Args:
        artifacts (list): A list of artifacts.

    Returns:
        tuple: Two lists containing the individual scores and confidences.
    """
    scores = []
    confidences = []

    if not artifacts:
        return scores, confidences  # Return empty lists if there are no artifacts

    for artifact in artifacts:
        if artifact.artifact_type == 'IP':
            score = artifact.artifactIsIp.ip.ioc_score
            confidence = artifact.artifactIsIp.ip.ioc_confidence
        elif artifact.artifact_type == 'URL':
            score = artifact.artifactIsUrl.url.ioc_score
            confidence = artifact.artifactIsUrl.url.ioc_confidence
        elif artifact.artifact_type == 'Hash':
            score = artifact.artifactIsHash.hash.ioc_score
            confidence = artifact.artifactIsHash.hash.ioc_confidence

        # Add to lists of scores and confidences
        scores.append(score)
        confidences.append(confidence)

    # Return lists of scores and confidences
    return scores, confidences

def calculate_body_score(case):
    """Calculate the body score and confidence for a given case.

    Args:
        case (Type): The case object containing the file or mail information.

    Returns:
        tuple: A tuple containing the body score and confidence.
    """
    score = 0
    confidence = 0
    if case.fileOrMail.mail:
        score += case.fileOrMail.mail.mail_body.body_score
        confidence += case.fileOrMail.mail.mail_body.body_confidence
    return score, confidence

def calculate_header_score(case):
    """Calculate the header score and confidence for a given case.

    Args:
        case (Case): The case object containing the file or mail information.

    Returns:
        tuple: A tuple containing the header score and confidence.
    """
    score = 0
    confidence = 0
    if case.fileOrMail.mail:
        score += case.fileOrMail.mail.mail_header.header_score
        confidence += case.fileOrMail.mail.mail_header.header_confidence
    return score, confidence

def calculate_file_score(case):
    """
    Calculate the file score and confidence for a given case.

    Args:
        case (Type): The case object containing file information.

    Returns:
        tuple: A tuple containing the calculated score and confidence.
    """
    score = 0
    confidence = 0
    if case.fileOrMail.file:
        score += case.fileOrMail.file.file_score + case.fileOrMail.file.linked_hash.ioc_score
        confidence += case.fileOrMail.file.file_confidence + case.fileOrMail.file.linked_hash.ioc_confidence
    return score, confidence

def calculate_non_file_ioc_scores(case):
    """Calculate the total score and confidence for non-file IOCs in a given case.

    Args:
        case (Case): The case object containing non-file IOCs.

    Returns:
        tuple: A tuple containing the total score and confidence for non-file IOCs.
    """
    score = 0
    confidence = 0
    if case.nonFileIocs:
        if case.nonFileIocs.ip:
            score += case.nonFileIocs.ip.ioc_score
            confidence += case.nonFileIocs.ip.ioc_confidence
        if case.nonFileIocs.url:
            score += case.nonFileIocs.url.ioc_score
            confidence += case.nonFileIocs.url.ioc_confidence
        if case.nonFileIocs.hash:
            score += case.nonFileIocs.hash.ioc_score
            confidence += case.nonFileIocs.hash.ioc_confidence
    return score, confidence

def calculate_total_scores(attachments, artifacts):
    """
    Calculate the total scores based on the number of attachments and artifacts.

    Args:
        attachments (list): A list of attachments.
        artifacts (list): A list of artifacts.

    Returns:
        int: The total scores calculated based on the number of attachments and artifacts.
    """
    total_attachments = len(attachments)
    total_artifacts = len(artifacts)
    total_scores = (total_attachments) + total_artifacts + 2 if total_attachments + total_artifacts > 0 else 1
    return total_scores

def calculate_result_ranges(final_score):
    """
    Calculate the result range based on the final score.

    Args:
        final_score (int): The final score to determine the result range.

    Returns:
        str: The result range based on the final score.

    Raises:
        None

    Examples:
        >>> calculate_result_ranges(3)
        'Safe'
        >>> calculate_result_ranges(5)
        'Inconclusive'
        >>> calculate_result_ranges(7)
        'Suspicious'
        >>> calculate_result_ranges(9)
        'Dangerous'
        >>> calculate_result_ranges(12)
        'Failure'
    """
    result_ranges = {
        (0, 4): "Safe",
        (5, 7): "Suspicious",
        (8, 10): "Dangerous",
    }

    # Default result for unknown scores or unexpected values
    default_result = "Failure"

    # Find the matching range for the final score
    for range_key in result_ranges:
        start, end = range_key
        if start <= final_score <= end:
            print(f"Final score {final_score} falls within range {start}-{end}")
            return result_ranges[range_key]
    print(f"Final score {final_score} does not fall within any range")
    return default_result

def get_ioc_score(level):
    """Get the IOC score based on the given level.

    Args:
        level (str): The level of the IOC (safe, suspicious, malicious).

    Returns:
        int: The IOC score corresponding to the given level. Returns None if the level is not found in the mapping.
    """
    score_mapping = {'safe': 0, 'suspicious': 7, 'malicious': 10}
    print(f"Getting IOC score for level: {level}")
    return score_mapping.get(level.lower(), None)