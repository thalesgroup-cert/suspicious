# score_process/scoring/processing.py
"""
Mail, attachment, and IOC scoring pipeline.
"""
import logging
from opentelemetry import trace

from django.db import transaction

from mail_feeder.models import MailArchive
from score_process.scoring.updating import (
    update_artifact_with_scores,
    update_file_with_scores,
    update_mail_part_with_scores,
)

logger              = logging.getLogger(__name__)
update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")
_tracer = trace.get_tracer(__name__)


# ── Prefetch constants ────────────────────────────────────────────────────────

_PROCESS_MAIL_PREFETCH = (
    "mail_attachments__file",
    "mail_artifacts__artifactIsIp__ip",
    "mail_artifacts__artifactIsUrl__url",
    "mail_artifacts__artifactIsHash__hash",
    "mail_artifacts__artifactIsDomain__domain",
    "mail_artifacts__artifactIsMailAddress__mail_address",
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def log_and_process(
    item, process_func, item_name, reports,
    total_scores, total_confidences, is_malicious, case_id,
):
    update_cases_logger.info("Processing %s.", item_name)
    with _tracer.start_as_current_span("score.process_item") as span:
        span.set_attribute("item.type", item_name)
        span.set_attribute("case.id", case_id)
        try:
            failures = process_func(
                item, reports, total_scores, total_confidences, is_malicious, case_id
            )
        except (ValueError, TypeError, RuntimeError) as exc:
            span.record_exception(exc)
            update_cases_logger.exception("Error processing %s: %s", item_name, exc)
            failures = 1
    update_cases_logger.info("Finished processing %s.", item_name)
    return failures


def compute_weighted_scores(reports, label):
    """
    Return (weighted_score, weighted_confidence, total_weight).

    Raises ValueError when total_weight is zero so callers get a clear
    signal rather than (0, 0, 0) which looks like a legitimate result.
    """
    total_weight = sum(r.analyzer.weight for r in reports)
    if total_weight == 0:
        raise ValueError("Total analyzer weight is zero for %s — cannot compute scores." % label)

    valid = [r for r in reports if r.status != "Failure"]
    weighted_score      = round(sum(r.score      * r.analyzer.weight for r in valid) / total_weight)
    weighted_confidence = round(sum(r.confidence * r.analyzer.weight for r in valid) / total_weight) * 10
    return weighted_score, weighted_confidence, total_weight


def process_reports(analyzers_reports, mail_part, part_type, is_malicious):
    """
    Compute weighted score/confidence from a list of reports and write
    them onto mail_part.score / mail_part.confidence.

    Returns (score, confidence).
    Raises ValueError when reports is empty or total weight is zero.
    """
    if not analyzers_reports:
        raise ValueError("No reports available for %s." % part_type)

    score, confidence, _ = compute_weighted_scores(analyzers_reports, part_type)
    mail_part.score      = score
    mail_part.confidence = confidence
    update_cases_logger.info(
        "Computed %s score=%s confidence=%s.", part_type, score, confidence
    )
    return score, confidence


# ── Mail processing ───────────────────────────────────────────────────────────

def process_mail(mail, reports, total_scores, total_confidences, is_malicious, case_id):
    from mail_feeder.models import Mail  # local import: avoid app-loading cycle
    mail = Mail.objects.prefetch_related(*_PROCESS_MAIL_PREFETCH).get(pk=mail.pk)
    total_failures = 0
    update_cases_logger.info("Starting mail processing.")
    mail_archive = MailArchive.objects.filter(mail=mail).first()

    if mail.mail_body:
        total_failures += log_and_process(
            mail.mail_body, process_mail_body, "mail body",
            reports, total_scores, total_confidences, is_malicious, case_id,
        )

    if mail.mail_header:
        total_failures += log_and_process(
            mail.mail_header, process_mail_header, "mail header",
            reports, total_scores, total_confidences, is_malicious, case_id,
        )

    if mail_archive:
        total_failures += log_and_process(
            mail_archive, process_archive,
            "mail_archive %s" % mail_archive.id,
            reports, total_scores, total_confidences, is_malicious, case_id,
        )

    if mail.mail_attachments:
        update_cases_logger.info("Processing mail attachments.")
        for attachment in mail.mail_attachments.all():
            total_failures += log_and_process(
                attachment, process_attachment,
                "attachment %s" % attachment.id,
                reports, total_scores, total_confidences, is_malicious, case_id,
            )

    if hasattr(mail, "mail_artifacts"):
        update_cases_logger.info("Processing mail artifacts.")
        for artifact in mail.mail_artifacts.all():
            total_failures += log_and_process(
                artifact, process_mail_artifact,
                "artifact %s" % artifact.id,
                reports, total_scores, total_confidences, is_malicious, case_id,
            )

    update_cases_logger.info("Finished mail processing.")
    return total_failures


def _process_mail_part(
    mail_part, part_type, score_field, confidence_field,
    reports, total_scores, total_confidences, is_malicious, log_func,
):
    from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

    failure = 0
    log_func("process_%s: starting.", part_type)
    try:
        mail_part.times_sent += 1
        analyzer_reports = CortexAnalyzerReports.get_analyzer_reports_by_type_and_artifact(
            part_type, mail_part
        )

        if analyzer_reports:
            failure += CortexAnalyzerReports.process_analyzer_reports(
                reports, analyzer_reports, mail_part.fuzzy_hash, None
            )

            score, confidence = process_reports(
                analyzer_reports, mail_part, part_type, is_malicious
            )
            total_scores.append(score)
            total_confidences.append(confidence)

            setattr(mail_part, score_field,      score)
            setattr(mail_part, confidence_field, confidence)

            update_mail_part_with_scores(mail_part, part_type, is_malicious)
            # Only write the fields we changed
            mail_part.save(update_fields=["times_sent", score_field, confidence_field])
            log_func("process_%s: saved successfully.", part_type)

    except (ValueError, TypeError, RuntimeError) as exc:
        log_func("process_%s: error — %s", part_type, exc)
        failure += 1

    return failure


def process_mail_header(mail_header, reports, total_scores, total_confidences, is_malicious, case_id):
    return _process_mail_part(
        mail_part=mail_header, part_type="mail_header",
        score_field="header_score", confidence_field="header_confidence",
        reports=reports, total_scores=total_scores, total_confidences=total_confidences,
        is_malicious=is_malicious, log_func=update_cases_logger.debug,
    )


def process_mail_body(mail_body, reports, total_scores, total_confidences, is_malicious, case_id):
    return _process_mail_part(
        mail_part=mail_body, part_type="mail_body",
        score_field="body_score", confidence_field="body_confidence",
        reports=reports, total_scores=total_scores, total_confidences=total_confidences,
        is_malicious=is_malicious, log_func=update_cases_logger.info,
    )


# ── IOC processing ────────────────────────────────────────────────────────────

def process_ioc(ioc, ioc_type, reports, total_scores, total_confidences, is_malicious):
    from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

    failure = 0
    try:
        ioc.times_sent += 1
        ioc.save(update_fields=["times_sent"])

        analyzer_reports = CortexAnalyzerReports.get_analyzer_reports_by_type_and_artifact(
            ioc_type, ioc
        )
        update_cases_logger.debug("Analyzer reports retrieved for %s IOC.", ioc_type)

        if not analyzer_reports:
            return failure

        artifact_value = ioc.value if ioc_type in ("hash", "domain") else ioc.address
        failure = CortexAnalyzerReports.process_analyzer_reports(
            reports, analyzer_reports, artifact_value, None
        )

        try:
            ioc.ioc_score, ioc.ioc_confidence, _ = compute_weighted_scores(
                [r for r in analyzer_reports if r.status != "Failure"],
                ioc_type,
            )
        except ValueError:
            update_cases_logger.warning(
                "No valid analyzer weights for %s IOC — defaulting scores to 0.", ioc_type
            )
            ioc.ioc_score      = 0
            ioc.ioc_confidence = 0

        update_artifact_with_scores(ioc, is_malicious)
        total_scores.append(ioc.ioc_score)
        total_confidences.append(ioc.ioc_confidence)
        update_cases_logger.debug(
            "%s IOC scored: score=%s confidence=%s.", ioc_type, ioc.ioc_score, ioc.ioc_confidence
        )

    except (ValueError, TypeError, RuntimeError) as exc:
        update_cases_logger.error("Error processing %s IOC: %s", ioc_type, exc, exc_info=True)
        failure = 1

    return failure


# ── File IOC base (shared by process_file_ioc and process_archive_ioc) ────────

def _process_file_ioc_base(
    file_ioc, reports, total_scores, total_confidences,
    is_malicious, case_id, *, include_linked_hash: bool,
):
    """
    Core file-IOC scoring logic.

    When include_linked_hash=True the linked hash (if present) is also
    scored and its weight is combined into the final file score —
    this is the behaviour for attachments.

    When include_linked_hash=False only the file itself is scored —
    this is the behaviour for archive entries which have no linked hash.
    """
    from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

    failure = 0
    try:
        file_ioc.times_sent += 1
        file_ioc.save(update_fields=["times_sent"])

        analyzers_reports_file = CortexAnalyzerReports.get_analyzer_reports_by_type_and_artifact(
            "file", file_ioc
        )
        if not analyzers_reports_file:
            return failure

        failure = CortexAnalyzerReports.process_analyzer_reports(
            reports, analyzers_reports_file, str(file_ioc.file_path.name), case_id
        )

        try:
            file_score, file_confidence, file_weight = compute_weighted_scores(
                analyzers_reports_file, "file"
            )
        except ValueError:
            update_cases_logger.warning("Zero analyzer weight for file %r — defaulting to 0.", file_ioc)
            file_score, file_confidence, file_weight = 0, 0, 0

        if include_linked_hash and getattr(file_ioc, "linked_hash", None):
            analyzers_reports_hash = CortexAnalyzerReports.get_analyzer_reports_by_type_and_artifact(
                "hash", file_ioc.linked_hash
            )
            try:
                hash_score, hash_confidence, hash_weight = compute_weighted_scores(
                    analyzers_reports_hash, "hash"
                )
            except ValueError:
                update_cases_logger.warning(
                    "Zero weight for linked hash of %r — using file score only.", file_ioc
                )
                hash_score, hash_confidence, hash_weight = 0, 0, 0

            file_ioc.linked_hash.ioc_score      = hash_score
            file_ioc.linked_hash.ioc_confidence = hash_confidence
            update_artifact_with_scores(file_ioc.linked_hash, is_malicious)
            file_ioc.linked_hash.save(update_fields=["ioc_score", "ioc_confidence"])

            combined_weight = file_weight + hash_weight
            if combined_weight > 0:
                combined_score      = round((file_score * file_weight + hash_score * hash_weight) / combined_weight)
                combined_confidence = round((file_confidence * file_weight + hash_confidence * hash_weight) / combined_weight)
            else:
                combined_score, combined_confidence = file_score, file_confidence
        else:
            combined_score, combined_confidence = file_score, file_confidence

        file_ioc.file_score      = combined_score
        file_ioc.file_confidence = combined_confidence
        update_file_with_scores(file_ioc, is_malicious)

        total_scores.append(file_ioc.file_score)
        total_confidences.append(file_ioc.file_confidence)
        update_cases_logger.debug(
            "File IOC %r scored: score=%s confidence=%s (linked_hash=%s).",
            file_ioc, combined_score, combined_confidence, include_linked_hash,
        )

    except (ValueError, TypeError, RuntimeError) as exc:
        update_cases_logger.error("Error processing file IOC %r: %s", file_ioc, exc, exc_info=True)
        failure += 1

    return failure


def process_file_ioc(file_ioc, reports, total_scores, total_confidences, is_malicious, case_id):
    """Process a file IOC, combining linked-hash scores when present."""
    return _process_file_ioc_base(
        file_ioc, reports, total_scores, total_confidences, is_malicious, case_id,
        include_linked_hash=True,
    )


def process_archive_ioc(file_ioc, reports, total_scores, total_confidences, is_malicious, case_id):
    """Process an archive file IOC — no linked-hash combination."""
    return _process_file_ioc_base(
        file_ioc, reports, total_scores, total_confidences, is_malicious, case_id,
        include_linked_hash=False,
    )


# ── Container processors ──────────────────────────────────────────────────────

def process_archive(archive, reports, total_scores, total_confidences, is_malicious, case_id):
    failure_count = 0
    try:
        with transaction.atomic():
            file_ioc = archive.archive
            if not file_ioc:
                update_cases_logger.warning("No file IOC found for archive %r.", archive)
                return 1
            failure_count += process_archive_ioc(
                file_ioc, reports, total_scores, total_confidences, is_malicious, case_id
            )
    except (ValueError, TypeError, RuntimeError) as exc:
        update_cases_logger.error("Error processing archive %r: %s", archive, exc, exc_info=True)
        failure_count += 1
    return failure_count


def process_attachment(attachment, reports, total_scores, total_confidences, is_malicious, case_id):
    failure_count = 0
    try:
        with transaction.atomic():
            file_ioc = attachment.file
            if not file_ioc:
                update_cases_logger.warning("No file IOC found for attachment %r.", attachment)
                return 1
            failure_count += process_file_ioc(
                file_ioc, reports, total_scores, total_confidences, is_malicious, case_id
            )
    except (ValueError, TypeError, RuntimeError) as exc:
        update_cases_logger.error("Error processing attachment %r: %s", attachment, exc, exc_info=True)
        failure_count += 1
    return failure_count


def process_mail_artifact(artifact, reports, total_scores, total_confidences, is_malicious, case_id):
    failure_count = 0
    try:
        with transaction.atomic():
            artifact_type = artifact.artifact_type.lower()
            SUPPORTED = {"url", "ip", "hash", "domain", "mailaddress"}
            if artifact_type not in SUPPORTED:
                update_cases_logger.warning(
                    "Unsupported artifact type %r — skipping.", artifact_type
                )
                return 0

            artifact_obj = getattr(artifact, "artifactIs%s" % artifact_type.capitalize(), None)
            if not artifact_obj:
                update_cases_logger.warning(
                    "No object for artifact type %r on %r.", artifact_type, artifact
                )
                return 1

            artifact_obj.times_sent += 1
            artifact_obj.save(update_fields=["times_sent"])

            instance = getattr(artifact_obj, artifact_type, None)
            if not instance:
                update_cases_logger.warning(
                    "Missing instance for artifact type %r on %r.", artifact_type, artifact_obj
                )
                return 1

            failure_count += process_ioc(
                instance, artifact_type, reports, total_scores, total_confidences, is_malicious
            )

    except (ValueError, TypeError, RuntimeError) as exc:
        update_cases_logger.error(
            "Error processing mail artifact %r: %s", artifact, exc, exc_info=True
        )
        failure_count += 1
    return failure_count