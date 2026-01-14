""" This module contains functions to process mail, mail artifacts, and IOCs."""
import logging
from django.db import transaction
from score_process.scoring.updating import update_file_with_scores, update_artifact_with_scores, update_mail_part_with_scores
from mail_feeder.models import MailArchive

logger = logging.getLogger(__name__)
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')


def log_and_process(item, process_func, item_name, reports, total_scores,
                    total_confidences, is_malicious, case_id):
    """
    Helper function that logs the start and end of a processing step,
    and handles exceptions gracefully.
    """
    update_cases_logger.info("Processing %s.", item_name)
    try:
        failures = process_func(item, reports, total_scores, total_confidences, is_malicious, case_id)
    except (ValueError, TypeError, RuntimeError) as e:
        update_cases_logger.exception("Error processing %s: %s", item_name, e)
        failures = 1  # You can adjust the failure count as needed.
    update_cases_logger.info("Finished processing %s.", item_name)
    return failures


def process_mail(mail, reports, total_scores, total_confidences, is_malicious, case_id):
    """
    Process the given mail by analyzing its body, header, attachments, and artifacts.

    Args:
        mail (Mail): The mail object to process.
        reports (list): A list to store the generated reports.
        total_scores (dict): A dictionary to store the total scores.
        total_confidences (dict): A dictionary to store the total confidences.
        is_malicious (bool): A flag indicating whether the mail is malicious or not.

    Returns:
        int: The total number of failures encountered during the processing.
    """
    total_failures = 0
    update_cases_logger.info("Starting mail processing.")
    mail_archive = MailArchive.objects.filter(mail=mail).first()

    # with transaction.atomic():
    if mail.mail_body:
        total_failures += log_and_process(
            mail.mail_body,
            process_mail_body,
            "mail body",
            reports,
            total_scores,
            total_confidences,
            is_malicious,
            case_id
        )

    if mail.mail_header:
        total_failures += log_and_process(
            mail.mail_header,
            process_mail_header,
            "mail header",
            reports,
            total_scores,
            total_confidences,
            is_malicious,
            case_id
        )

    if mail_archive:
        total_failures += log_and_process(
            mail_archive,
            process_archive,
            f"mail_archive {mail_archive.id}",
            reports,
            total_scores,
            total_confidences,
            is_malicious,
            case_id
        )

    if mail.mail_attachments:
        update_cases_logger.info("Processing mail attachments.")
        for attachment in mail.mail_attachments.all():
            total_failures += log_and_process(
                attachment,
                process_attachment,
                f"attachment {attachment.id}",
                reports,
                total_scores,
                total_confidences,
                is_malicious,
                case_id
            )
        update_cases_logger.info("Finished processing mail attachments.")

    # Check if mail has artifacts before iterating over them.
    if hasattr(mail, 'mail_artifacts'):
        update_cases_logger.info("Processing mail artifacts.")
        for artifact in mail.mail_artifacts.all():
            total_failures += log_and_process(
                artifact,
                process_mail_artifact,
                f"artifact {artifact.id}",
                reports,
                total_scores,
                total_confidences,
                is_malicious,
                case_id
            )
        update_cases_logger.info("Finished processing mail artifacts.")

    update_cases_logger.info("Finished mail processing.")
    return total_failures


def _process_mail_part(mail_part, part_type, score_field, confidence_field, reports, total_scores, total_confidences, is_malicious, log_func):
    """
    Helper to process a mail part (header or body).

    Args:
        mail_part: The mail part (header or body) object.
        part_type (str): A string indicating the type (e.g. "mail_header", "mail_body").
        score_field (str): The attribute name to set the computed score.
        confidence_field (str): The attribute name to set the computed confidence.
        reports (list): List of analyzer reports.
        total_scores (list): List to store total scores.
        total_confidences (list): List to store total confidences.
        is_malicious (bool): Flag indicating if the part is malicious.
        log_func (callable): Logging function to use (e.g. update_cases_logger.debug/info).

    Returns:
        int: A failure counter (0 if all went well; >0 otherwise).
    """
    from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
    failure = 0
    log_func(f"process_{part_type}: processing {part_type}.")
    try:
        mail_part.times_sent += 1
        # Retrieve analyzer reports using a fuzzy hash for the part
        analyzer_reports = CortexAnalyzerReports.get_analyzer_reports_by_type_and_artifact(part_type, mail_part)
        log_func(f"process_{part_type}: analyzer reports retrieved.")

        if analyzer_reports:
            failure += CortexAnalyzerReports.process_analyzer_reports(reports, analyzer_reports, mail_part.fuzzy_hash, None)
            log_func(f"process_{part_type}: analyzer reports processed.")

            # Calculate the score and confidence from reports
            score, confidence = process_reports(analyzer_reports, mail_part, part_type, is_malicious)
            total_scores.append(score)
            total_confidences.append(confidence)

            # Update the mail part's score/confidence attributes
            setattr(mail_part, score_field, score)
            setattr(mail_part, confidence_field, confidence)

            # Update score levels and persist changes
            update_mail_part_with_scores(mail_part, part_type, is_malicious)
            mail_part.save()
            log_func(f"process_{part_type}: {part_type} processed and saved successfully.")
    except (ValueError, TypeError, RuntimeError) as e:
        log_func(f"process_{part_type}: error processing {part_type}: {e}")
        failure += 1
    return failure


def process_mail_header(mail_header, reports, total_scores, total_confidences, is_malicious, case_id):
    """
    Process the mail header by analyzing its contents and updating its score and confidence.
    """
    # For mail header, we use debug-level logging.
    return _process_mail_part(
        mail_part=mail_header,
        part_type="mail_header",
        score_field="header_score",
        confidence_field="header_confidence",
        reports=reports,
        total_scores=total_scores,
        total_confidences=total_confidences,
        is_malicious=is_malicious,
        log_func=update_cases_logger.debug
    )


def process_mail_body(mail_body, reports, total_scores, total_confidences, is_malicious, case_id):
    """
    Process the mail body by analyzing its contents and updating its score and confidence.
    """
    # For mail body, we use info-level logging for the high-level messages.
    return _process_mail_part(
        mail_part=mail_body,
        part_type="mail_body",
        score_field="body_score",
        confidence_field="body_confidence",
        reports=reports,
        total_scores=total_scores,
        total_confidences=total_confidences,
        is_malicious=is_malicious,
        log_func=update_cases_logger.info
    )


def process_ioc(ioc, ioc_type, reports, total_scores, total_confidences, is_malicious):
    """
    Process an IOC (Indicator of Compromise) and calculate its score and confidence.

    Args:
        ioc: The IOC object to process.
        ioc_type: The type of the IOC (e.g., "hash", "address").
        reports: The list to which analyzer reports are appended.
        total_scores: A list to store the total scores.
        total_confidences: A list to store the total confidences.
        is_malicious: A boolean indicating whether the IOC is malicious.

    Returns:
        int: A failure indicator (0 if processing was successful, non-zero otherwise).
    """
    from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
    failure = 0
    try:
        # Increment times_sent and save the IOC.
        ioc.times_sent += 1
        ioc.save()

        update_cases_logger.debug("Processing %s IOC (times_sent=%d).", ioc_type, ioc.times_sent)
        analyzer_reports = CortexAnalyzerReports.get_analyzer_reports_by_type_and_artifact(ioc_type, ioc)
        update_cases_logger.debug("Analyzer reports retrieved.")

        if analyzer_reports:
            # Use ioc.value for "hash" type, otherwise use ioc.address.
            artifact_value = ioc.value if ioc_type == "hash" else ioc.address
            failure = CortexAnalyzerReports.process_analyzer_reports(reports, analyzer_reports, artifact_value, None)
            update_cases_logger.debug("Analyzer reports processed.")

            weighted_scores = []
            weighted_confidences = []
            total_weight = 0

            for report in analyzer_reports:
                # Only consider reports that did not fail.
                if report.status == "Failure":
                    continue
                weight = report.analyzer.weight
                weighted_scores.append(report.score * weight)
                weighted_confidences.append(report.confidence * weight)
                total_weight += weight

            update_cases_logger.debug("All valid reports calculated.")
            if total_weight > 0:
                ioc.ioc_score = round(sum(weighted_scores) / total_weight)
                ioc.ioc_confidence = round(sum(weighted_confidences) / total_weight) * 10
            else:
                update_cases_logger.warning("No valid analyzer weights for %s IOC. Defaulting scores to 0.", ioc_type)
                ioc.ioc_score = 0
                ioc.ioc_confidence = 0

            update_cases_logger.debug("%s score: %d", ioc_type.capitalize(), ioc.ioc_score)
            update_cases_logger.debug("%s confidence: %d", ioc_type.capitalize(), ioc.ioc_confidence)

            update_artifact_with_scores(ioc, is_malicious)
            update_cases_logger.debug("Final %s score updated: %d", ioc_type, ioc.ioc_score)
            total_scores.append(ioc.ioc_score)
            update_cases_logger.debug("Total score appended: %s", ioc.ioc_score)
            total_confidences.append(ioc.ioc_confidence)
            update_cases_logger.debug("Total confidence appended: %d", ioc.ioc_confidence)

            if total_scores:
                avg_score = sum(total_scores) / len(total_scores)
                avg_confidence = sum(total_confidences) / len(total_confidences)
                update_cases_logger.debug("Average score: %s", avg_score)
                update_cases_logger.debug("Average confidence: %s", avg_confidence)

    except (ValueError, TypeError, RuntimeError) as e:
        update_cases_logger.error("Error processing %s IOC: %s", ioc_type, e, exc_info=True)
        failure = 1

    return failure


def compute_weighted_scores(reports, label):
    """
    Given a list of analyzer reports, compute a weighted average score and confidence.
    The confidence is scaled by 10 (as in your original code).

    Args:
        reports (list): List of analyzer reports.
        label (str): A string label used for error messages.

    Returns:
        tuple: (weighted_score, weighted_confidence, total_weight)
    Raises:
        ValueError: If total weight is zero.
    """
    total_weight = sum(report.analyzer.weight for report in reports)
    if total_weight == 0:
        update_cases_logger.error(f"Total weight cannot be zero when processing {label} IOC.")
        return 0, 0, 0
    valid_scores = [report.score * report.analyzer.weight for report in reports if report.status != "Failure"]
    valid_confidences = [report.confidence * report.analyzer.weight for report in reports if report.status != "Failure"]
    weighted_score = round(sum(valid_scores) / total_weight)
    weighted_confidence = round(sum(valid_confidences) / total_weight) * 10
    return weighted_score, weighted_confidence, total_weight


def process_file_ioc(file_ioc, reports, total_scores, total_confidences, is_malicious, case_id):
    """
    Process the file IOC by computing weighted scores and confidences.
    If the file IOC has a linked hash, its weighted scores are computed and aggregated.
    Finally, the file IOC is updated with the aggregated score/confidence, which are then added to the totals.

    Args:
        file_ioc (FileIOC): The file IOC object.
        reports (list): List to which analyzer reports are appended.
        total_scores (list[float]): List of accumulated scores.
        total_confidences (list[float]): List of accumulated confidences.
        is_malicious (bool): Whether the file is malicious.

    Returns:
        int: The failure count (0 if processing is successful; nonzero otherwise).
    """
    from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
    failure = 0

    try:
        # Update times_sent and persist the change.
        file_ioc.times_sent += 1
        file_ioc.save()
        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: processing file (times_sent={file_ioc.times_sent})."
        )

        # Retrieve analyzer reports for the file.
        analyzers_reports_file = CortexAnalyzerReports.get_analyzer_reports_by_type_and_artifact("file", file_ioc)
        update_cases_logger.debug("[score_check.py] process_file_ioc: file analyzer reports retrieved.")

        # If there are no analyzer reports, we can exit early.
        if not analyzers_reports_file:
            return failure

        # Process file analyzer reports and update failure count.
        failure = CortexAnalyzerReports.process_analyzer_reports(
            reports, analyzers_reports_file, str(file_ioc.file_path.name), case_id
        )

        # Compute weighted score/confidence for the file IOC.
        file_score, file_confidence, file_weight = compute_weighted_scores(analyzers_reports_file, "file")
        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: file score: {file_score}, confidence: {file_confidence}."
        )
        update_cases_logger.debug("[score_check.py] process_file_ioc: file analyzer reports processed.")

        # Process linked hash if available.
        if file_ioc.linked_hash:
            analyzers_reports_hash = CortexAnalyzerReports.get_analyzer_reports_by_type_and_artifact("hash", file_ioc.linked_hash)
            hash_score, hash_confidence, hash_weight = compute_weighted_scores(analyzers_reports_hash, "hash")
            update_cases_logger.debug("[score_check.py] process_file_ioc: hash analyzer reports processed.")

            # Update the linked hash IOC.
            file_ioc.linked_hash.ioc_score = hash_score
            file_ioc.linked_hash.ioc_confidence = hash_confidence
            update_artifact_with_scores(file_ioc.linked_hash, is_malicious)
            file_ioc.linked_hash.save()
            update_cases_logger.debug(
                f"[score_check.py] process_file_ioc: linked hash score: {hash_score}, confidence: {hash_confidence}."
            )

            # Aggregate file and hash results using weighted average.
            combined_weight = file_weight + hash_weight
            combined_score = round((file_score * file_weight + hash_score * hash_weight) / combined_weight)
            combined_confidence = round((file_confidence * file_weight + hash_confidence * hash_weight) / combined_weight)
        else:
            combined_score, combined_confidence = round(file_score), round(file_confidence)

        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: {file_ioc.file_path.name} combined score: {combined_score}."
        )
        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: combined confidence: {combined_confidence}."
        )

        # Update the file IOC with the aggregated values.
        file_ioc.file_score = combined_score
        file_ioc.file_confidence = combined_confidence
        update_cases_logger.debug(f"[score_check.py] process_file_ioc: file score set to {file_ioc.file_score}.")
        update_cases_logger.debug(f"[score_check.py] process_file_ioc: file confidence set to {file_ioc.file_confidence}.")

        update_file_with_scores(file_ioc, is_malicious)
        update_cases_logger.debug(f"[score_check.py] process_file_ioc: final file score updated: {file_ioc.file_score}.")

        # Append the computed values to the totals.
        total_scores.append(file_ioc.file_score)
        total_confidences.append(file_ioc.file_confidence)
        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: total score: {sum(total_scores) / len(total_scores)}."
        )
        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: total confidence: {sum(total_confidences) / len(total_confidences)}."
        )

    except (ValueError, TypeError, RuntimeError) as e:
        update_cases_logger.error(
            f"[score_check.py] process_file_ioc: error processing file: {e}",
            exc_info=True
        )
        failure += 1

    return failure

def process_archive_ioc(file_ioc, reports, total_scores, total_confidences, is_malicious, case_id):
    """
    Process the file IOC by computing weighted scores and confidences.
    If the file IOC has a linked hash, its weighted scores are computed and aggregated.
    Finally, the file IOC is updated with the aggregated score/confidence, which are then added to the totals.

    Args:
        file_ioc (FileIOC): The file IOC object.
        reports (list): List to which analyzer reports are appended.
        total_scores (list[float]): List of accumulated scores.
        total_confidences (list[float]): List of accumulated confidences.
        is_malicious (bool): Whether the file is malicious.

    Returns:
        int: The failure count (0 if processing is successful; nonzero otherwise).
    """
    from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
    failure = 0

    try:
        # Update times_sent and persist the change.
        file_ioc.times_sent += 1
        file_ioc.save()
        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: processing file (times_sent={file_ioc.times_sent})."
        )

        # Retrieve analyzer reports for the file.
        analyzers_reports_file = CortexAnalyzerReports.get_analyzer_reports_by_type_and_artifact("file", file_ioc)
        update_cases_logger.debug("[score_check.py] process_file_ioc: file analyzer reports retrieved.")

        # If there are no analyzer reports, we can exit early.
        if not analyzers_reports_file:
            return failure

        # Process file analyzer reports and update failure count.
        failure = CortexAnalyzerReports.process_analyzer_reports(
            reports, analyzers_reports_file, str(file_ioc.file_path.name), case_id
        )

        # Compute weighted score/confidence for the file IOC.
        file_score, file_confidence, file_weight = compute_weighted_scores(analyzers_reports_file, "file")
        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: file score: {file_score}, confidence: {file_confidence}."
        )
        update_cases_logger.debug("[score_check.py] process_file_ioc: file analyzer reports processed.")

        
        combined_score, combined_confidence = round(file_score), round(file_confidence)

        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: {file_ioc.file_path.name} combined score: {combined_score}."
        )
        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: combined confidence: {combined_confidence}."
        )

        # Update the file IOC with the aggregated values.
        file_ioc.file_score = combined_score
        file_ioc.file_confidence = combined_confidence
        update_cases_logger.debug(f"[score_check.py] process_file_ioc: file score set to {file_ioc.file_score}.")
        update_cases_logger.debug(f"[score_check.py] process_file_ioc: file confidence set to {file_ioc.file_confidence}.")

        update_file_with_scores(file_ioc, is_malicious)
        update_cases_logger.debug(f"[score_check.py] process_file_ioc: final file score updated: {file_ioc.file_score}.")

        # Append the computed values to the totals.
        total_scores.append(file_ioc.file_score)
        total_confidences.append(file_ioc.file_confidence)
        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: total score: {sum(total_scores) / len(total_scores)}."
        )
        update_cases_logger.debug(
            f"[score_check.py] process_file_ioc: total confidence: {sum(total_confidences) / len(total_confidences)}."
        )

    except (ValueError, TypeError, RuntimeError) as e:
        update_cases_logger.error(
            f"[score_check.py] process_file_ioc: error processing file: {e}",
            exc_info=True
        )
        failure += 1

    return failure

def process_archive(archive, reports, total_scores, total_confidences, is_malicious, case_id):
    """
    Processes an archive by handling its associated file IOC and linked hash.
    Aggregates scores and updates reports accordingly.

    Args:
        archive: The archive to be processed.
        reports (list): List of reports to be updated.
        total_scores (list): Accumulator for total scores.
        total_confidences (list): Accumulator for total confidences.
        is_malicious (bool): Flag indicating if the archive is malicious.

    Returns:
        int: The number of failures encountered during processing.
    """
    failure_count = 0

    try:
        update_cases_logger.debug("[score_check.py] process_archive: Starting processing.")

        with transaction.atomic():
            file_ioc = archive.archive
            if not file_ioc:
                update_cases_logger.warning("[score_check.py] process_archive: No file IOC found for archive.")
                return 1  # Consider an archive without a file as a failure

            update_cases_logger.info("[score_check.py] process_archive: Processing file: %s", file_ioc)

            # Process the file IOC, which includes handling its linked hash if present
            failure_count += process_archive_ioc(file_ioc, reports, total_scores, total_confidences, is_malicious, case_id)

            update_cases_logger.debug("[score_check.py] process_archive: Finished processing file IOC: %s", file_ioc)

    except (ValueError, TypeError, RuntimeError) as e:
        update_cases_logger.error("[score_check.py] process_archive: Error processing archive: %s", e, exc_info=True)
        failure_count += 1  # Ensure failure count increments if an error occurs

    return failure_count

def process_attachment(attachment, reports, total_scores, total_confidences, is_malicious, case_id):
    """
    Processes an attachment by handling its associated file IOC and linked hash.
    Aggregates scores and updates reports accordingly.

    Args:
        attachment: The attachment to be processed.
        reports (list): List of reports to be updated.
        total_scores (list): Accumulator for total scores.
        total_confidences (list): Accumulator for total confidences.
        is_malicious (bool): Flag indicating if the attachment is malicious.

    Returns:
        int: The number of failures encountered during processing.
    """
    failure_count = 0

    try:
        update_cases_logger.debug("[score_check.py] process_attachment: Starting processing.")

        with transaction.atomic():
            file_ioc = attachment.file
            if not file_ioc:
                update_cases_logger.warning("[score_check.py] process_attachment: No file IOC found for attachment.")
                return 1  # Consider an attachment without a file as a failure

            update_cases_logger.info("[score_check.py] process_attachment: Processing file: %s", file_ioc)

            # Process the file IOC, which includes handling its linked hash if present
            failure_count += process_file_ioc(file_ioc, reports, total_scores, total_confidences, is_malicious, case_id)

            update_cases_logger.debug("[score_check.py] process_attachment: Finished processing file IOC: %s", file_ioc)

    except (ValueError, TypeError, RuntimeError) as e:
        update_cases_logger.error("[score_check.py] process_attachment: Error processing attachment: %s", e, exc_info=True)
        failure_count += 1  # Ensure failure count increments if an error occurs

    return failure_count

from django.db import transaction
import logging

update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def process_mail_artifact(artifact, reports, total_scores, total_confidences, is_malicious, case_id):
    """
    Processes a mail artifact (URL, IP, Hash, or Domain).
    Extracts the relevant artifact object, updates its score and confidence, and logs the process.

    Args:
        artifact: The mail artifact to process.
        reports (list): List of reports to update.
        total_scores (list): Accumulator for total scores.
        total_confidences (list): Accumulator for total confidences.
        is_malicious (bool): Indicates if the artifact is malicious.

    Returns:
        int: Number of failures encountered during processing.
    """
    failure_count = 0

    try:
        update_cases_logger.debug("[score_check.py] process_mail_artifact: Starting processing.")

        with transaction.atomic():
            artifact_type = artifact.artifact_type.lower()
            update_cases_logger.info("[score_check.py] process_mail_artifact: Processing artifact of type: %s", artifact_type)

            # Define a mapping for valid artifact types
            artifact_mapping = {
                "url": "url",
                "ip": "ip",
                "hash": "hash",
                "domain": "domain",
                "mailaddress": "mailaddress"
            }

            # Validate the artifact type
            if artifact_type not in artifact_mapping:
                update_cases_logger.warning("[score_check.py] process_mail_artifact: Unsupported artifact type: %s", artifact_type)
                return 0  # Unknown artifact types are considered failures

            # Retrieve the specific artifact object
            artifact_obj = getattr(artifact, f"artifactIs{artifact_type.capitalize()}", None)

            if not artifact_obj:
                update_cases_logger.warning("[score_check.py] process_mail_artifact: No corresponding object found for type '%s'.", artifact_type)
                return 1  # Missing artifact object is a failure

            # Increment times_sent and save
            artifact_obj.times_sent += 1
            artifact_obj.save()

            update_cases_logger.debug("[score_check.py] process_mail_artifact: Processing %s (times_sent= %d)", artifact_type, artifact_obj.times_sent)

            # Determine the correct instance to process
            instance = getattr(artifact_obj, artifact_mapping[artifact_type], None)

            if not instance:
                update_cases_logger.warning("[score_check.py] process_mail_artifact: Missing instance for type '%s'.", artifact_type)
                return 1  # Failure due to missing instance

            # Process the artifact
            failure_count += process_ioc(instance, artifact_type, reports, total_scores, total_confidences, is_malicious)

            update_cases_logger.debug("[score_check.py] process_mail_artifact: Completed processing of %s.", artifact_type)

    except (ValueError, TypeError, RuntimeError) as e:
        update_cases_logger.error("[score_check.py] process_mail_artifact: Error processing mail artifact: %s", e, exc_info=True)
        failure_count += 1  # Ensure failure count increments on error

    return failure_count


def process_reports(analyzers_reports, mail_part, part_type, is_malicious):
    """
    Processes analyzer reports to compute a weighted score and confidence level.

    Args:
        analyzers_reports (list): List of analyzer reports.
        mail_part (object): The mail part (e.g., attachment, artifact) being processed.
        part_type (str): The type of mail part being analyzed (e.g., "attachment", "artifact").
        is_malicious (bool): Indicates if the mail part is malicious.

    Returns:
        tuple: (final score, final confidence level)
    """
    if not analyzers_reports:
        raise ValueError(f"[score_check.py] process_{part_type}: No reports available for processing.")

    total_weight = sum(report.analyzer.weight for report in analyzers_reports)

    if total_weight == 0:
        raise ValueError(f"[score_check.py] process_{part_type}: Total weight is zero. Cannot process reports.")

    # Compute weighted score and confidence
    weighted_score = round(sum(report.score * report.analyzer.weight for report in analyzers_reports) / total_weight)
    weighted_confidence = round(sum(report.confidence * report.analyzer.weight for report in analyzers_reports) / total_weight) * 10  # Scale confidence

    # Update mail_part with computed values
    mail_part.score = weighted_score
    mail_part.confidence = weighted_confidence

    update_cases_logger.info(f"[score_check.py] process_{part_type}: Computed {part_type} score: {weighted_score}, confidence: {weighted_confidence}")

    return weighted_score, weighted_confidence