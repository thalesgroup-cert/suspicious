import math
import logging
from django.db import models
from django.utils import timezone

logger = logging.getLogger("tasp.submission_queue")

RETRY_BASE_DELAY_SECONDS = 60
RETRY_MAX_DELAY_SECONDS = 3600
RETRY_MAX_ATTEMPTS = 5


class SubmissionStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    PROCESSING = "processing", "Processing"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"
    RETRY = "retry", "Retry"


class ProcessingStage(models.TextChoices):
    """
    Ordered processing stages. Used to resume from the last completed stage
    on retry without restarting from scratch.
    """
    FETCHED = "fetched", "Fetched from MinIO"
    PARSED = "parsed", "Email parsed"
    MAIL_PERSISTED = "mail_persisted", "Mail + header + body persisted"
    ARTIFACTS_EXTRACTED = "artifacts_extracted", "Artifacts and attachments extracted"
    CASE_CREATED = "case_created", "Case created"
    NOTIFIED = "notified", "User notified"


STAGE_ORDER = [
    ProcessingStage.FETCHED,
    ProcessingStage.PARSED,
    ProcessingStage.MAIL_PERSISTED,
    ProcessingStage.ARTIFACTS_EXTRACTED,
    ProcessingStage.CASE_CREATED,
    ProcessingStage.NOTIFIED,
]


class SubmissionQueueManager(models.Manager):
    def claim_next(self, worker_id: str) -> "SubmissionQueue | None":
        """
        Atomically claim the next pending (or retry-ready) submission.
        Uses SELECT FOR UPDATE SKIP LOCKED to prevent concurrent workers
        from claiming the same row.

        Returns the claimed SubmissionQueue instance or None if the queue
        is empty.

        Usage:
            item = SubmissionQueue.objects.claim_next(worker_id="worker-1")
            if item:
                process(item)
        """
        from django.db import transaction

        with transaction.atomic():
            item = (
                self.select_for_update(skip_locked=True)
                .filter(
                    models.Q(status=SubmissionStatus.PENDING)
                    | models.Q(
                        status=SubmissionStatus.RETRY,
                        retry_after__lte=timezone.now(),
                    )
                )
                .order_by("created_at")
                .first()
            )

            if item is None:
                return None

            item.status = SubmissionStatus.PROCESSING
            item.locked_at = timezone.now()
            item.worker_id = worker_id
            item.save(update_fields=["status", "locked_at", "worker_id"])

        logger.info(
            "Worker %s claimed submission %s", worker_id, item.submission_id
        )
        return item

    def stale_processing(self, older_than_minutes: int = 30):
        """
        Return submissions stuck in PROCESSING for longer than
        `older_than_minutes`. Used by a watchdog cron to detect
        dead workers and requeue their items.
        """
        cutoff = timezone.now() - timezone.timedelta(minutes=older_than_minutes)
        return self.filter(status=SubmissionStatus.PROCESSING, locked_at__lt=cutoff)


class SubmissionQueue(models.Model):
    """
    Durable task queue for email submissions retrieved from MinIO.

    Replaces bucket-level tag polling (Status=To Do) with a proper DB queue
    that supports:
      - Atomic claim via SELECT FOR UPDATE SKIP LOCKED (no race conditions)
      - Per-stage resumption (no full reprocessing on partial failure)
      - Exponential backoff retry with a hard attempt cap
      - Full audit trail linking MinIO objects to DB entities

    Workflow:
        1. A submission arrives in MinIO (via webhook or periodic scan).
        2. An ingest endpoint (or lightweight scanner) inserts a row here
           with status=pending.
        3. The cron worker calls SubmissionQueue.objects.claim_next() and
           processes through the STAGE_ORDER stages.
        4. On success: status=done.
        5. On recoverable error: status=retry, retry_after set via backoff.
        6. On fatal error: status=failed, error_detail recorded.
    """

    # -- Identity --
    submission_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text=(
            "Globally unique ID for this submission. "
            "Matches the MinIO subdirectory name, e.g. '251215150557-388c4d591d6f'."
        ),
    )
    bucket_name = models.CharField(
        max_length=255,
        db_index=True,
        help_text="Source MinIO bucket name.",
    )
    minio_prefix = models.CharField(
        max_length=512,
        help_text=(
            "Object key prefix for all objects belonging to this submission, "
            "e.g. 'submissions/2025/12/251215150557-388c4d591d6f/'."
        ),
    )
    minio_manifest_key = models.CharField(
        max_length=512,
        blank=True,
        help_text=(
            "Full object key for the metadata.json manifest, "
            "e.g. 'submissions/2025/12/251215150557-388c4d591d6f/metadata.json'. "
            "Empty if the submission predates manifest support."
        ),
    )

    # -- Reporter --
    reported_by = models.EmailField(
        db_index=True,
        help_text=(
            "Email address of the reporter, extracted from metadata.json at "
            "ingest time. Eliminates the need to re-parse user_submission.eml."
        ),
    )

    # -- Linked DB entities (set after processing) --
    mail_id = models.IntegerField(
        null=True,
        blank=True,
        db_index=True,
        help_text="PK of the Mail row created during processing. Null until stage MAIL_PERSISTED.",
    )

    # -- Queue state --
    status = models.CharField(
        max_length=20,
        choices=SubmissionStatus.choices,
        default=SubmissionStatus.PENDING,
        db_index=True,
    )
    current_stage = models.CharField(
        max_length=40,
        choices=ProcessingStage.choices,
        blank=True,
        help_text=(
            "Last successfully completed processing stage. "
            "Used to resume processing without restarting from scratch."
        ),
    )

    # -- Retry / backoff --
    retry_count = models.PositiveSmallIntegerField(
        default=0,
        help_text="Number of retry attempts so far.",
    )
    retry_after = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Earliest time this item should be retried. Null when not in retry state.",
    )
    error_detail = models.TextField(
        blank=True,
        help_text="Last error message or traceback excerpt. Overwritten on each attempt.",
    )

    # -- Concurrency / audit --
    worker_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="Identifier of the worker that last claimed this item.",
    )
    locked_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the current worker claimed this item.",
    )
    submitted_at = models.DateTimeField(
        help_text="When the submission landed in MinIO (from metadata.json).",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = SubmissionQueueManager()

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["status", "retry_after"]),
            models.Index(fields=["status", "locked_at"]),
            models.Index(fields=["submission_id"]),
            models.Index(fields=["mail_id"]),
        ]
        verbose_name = "Submission queue item"
        verbose_name_plural = "Submission queue"

    def __str__(self):
        return (
            f"[{self.status.upper()}] {self.submission_id} "
            f"(stage={self.current_stage or 'not started'}, "
            f"retries={self.retry_count})"
        )

    # ------------------------------------------------------------------
    # Stage management
    # ------------------------------------------------------------------

    def advance_stage(self, stage: str) -> None:
        """
        Mark `stage` as successfully completed and persist.
        Call this at the end of each pipeline stage so that a crash
        mid-pipeline resumes from the correct point.
        """
        self.current_stage = stage
        self.updated_at = timezone.now()
        self.save(update_fields=["current_stage", "updated_at"])
        logger.debug(
            "Submission %s advanced to stage %s", self.submission_id, stage
        )

    def next_stage(self) -> str | None:
        """
        Return the next unprocessed stage name, or None if all stages are done.
        """
        if not self.current_stage:
            return STAGE_ORDER[0]
        try:
            idx = STAGE_ORDER.index(self.current_stage)
        except ValueError:
            logger.error(
                "Unknown current_stage '%s' for submission %s",
                self.current_stage,
                self.submission_id,
            )
            return None
        next_idx = idx + 1
        return STAGE_ORDER[next_idx] if next_idx < len(STAGE_ORDER) else None

    def is_complete(self) -> bool:
        return self.current_stage == ProcessingStage.NOTIFIED

    # ------------------------------------------------------------------
    # Terminal state helpers
    # ------------------------------------------------------------------

    def mark_done(self) -> None:
        """Mark this submission as fully and successfully processed."""
        self.status = SubmissionStatus.DONE
        self.worker_id = ""
        self.locked_at = None
        self.save(update_fields=["status", "worker_id", "locked_at", "updated_at"])
        logger.info("Submission %s marked DONE", self.submission_id)

    def mark_failed(self, reason: str) -> None:
        """
        Permanently fail this submission. No further retries will be attempted.
        Use for unrecoverable errors (corrupt .eml, schema mismatch, etc.).
        """
        self.status = SubmissionStatus.FAILED
        self.error_detail = reason[:4000]
        self.worker_id = ""
        self.locked_at = None
        self.save(
            update_fields=[
                "status", "error_detail", "worker_id", "locked_at", "updated_at"
            ]
        )
        logger.error(
            "Submission %s marked FAILED: %s", self.submission_id, reason[:200]
        )

    # ------------------------------------------------------------------
    # Retry / backoff
    # ------------------------------------------------------------------

    def schedule_retry(self, error: str) -> bool:
        """
        Schedule a retry with exponential backoff if attempts remain.
        Returns True if retry was scheduled, False if the item was permanently failed.

        Backoff: delay = min(base * 2^attempt, max_delay)
        With defaults: 60s, 120s, 240s, 480s, 960s (capped at 3600s).
        """
        self.error_detail = error[:4000]
        self.retry_count += 1

        if self.retry_count > RETRY_MAX_ATTEMPTS:
            self.mark_failed(
                f"Exceeded max retry attempts ({RETRY_MAX_ATTEMPTS}). "
                f"Last error: {error[:500]}"
            )
            return False

        delay = min(
            RETRY_BASE_DELAY_SECONDS * math.pow(2, self.retry_count - 1),
            RETRY_MAX_DELAY_SECONDS,
        )
        self.status = SubmissionStatus.RETRY
        self.retry_after = timezone.now() + timezone.timedelta(seconds=delay)
        self.worker_id = ""
        self.locked_at = None
        self.save(
            update_fields=[
                "status",
                "retry_count",
                "retry_after",
                "error_detail",
                "worker_id",
                "locked_at",
                "updated_at",
            ]
        )
        logger.warning(
            "Submission %s scheduled for retry %d/%d in %.0fs. Error: %s",
            self.submission_id,
            self.retry_count,
            RETRY_MAX_ATTEMPTS,
            delay,
            error[:200],
        )
        return True

    def release_lock(self) -> None:
        """
        Release a claimed item back to PENDING without recording an error.
        Used by the watchdog to recover items from dead workers.
        """
        self.status = SubmissionStatus.PENDING
        self.worker_id = ""
        self.locked_at = None
        self.save(update_fields=["status", "worker_id", "locked_at", "updated_at"])
        logger.warning(
            "Lock released for stale submission %s", self.submission_id
        )