from django.conf import settings
from django.db import models
from django.utils import timezone


class AiAssessment(models.Model):
    """The full AI result for one case (one row per case, upserted)."""

    class Result(models.TextChoices):
        SAFE = "SAFE"
        UNWANTED = "UNWANTED"
        DANGEROUS = "DANGEROUS"
        INCONCLUSIVE = "INCONCLUSIVE"

    case = models.OneToOneField(
        "case_handler.Case", on_delete=models.CASCADE, related_name="ai_assessment"
    )
    model_version = models.CharField(max_length=32)
    result = models.CharField(max_length=20, choices=Result.choices)
    sub_class = models.CharField(max_length=32, blank=True)
    score = models.FloatField()
    confidence = models.FloatField()  # percent, as in Case.confidence_ai
    probabilities = models.JSONField(default=dict)
    sub_probabilities = models.JSONField(default=dict)
    tier = models.CharField(max_length=8, blank=True)
    contributing_phrases = models.JSONField(default=list)
    similar_cases = models.JSONField(default=list)
    campaign_embedding = models.TextField(blank=True)
    embedding_version = models.CharField(max_length=16, default="cmp-e1")
    latency_ms = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class LabelRecord(models.Model):
    """One observation of a labelled mail. Append-only: only status, flag_reason
    and the resolution fields are ever updated."""

    class Source(models.TextChoices):
        IMAP_FOLDER = "imap_folder"
        ANALYST_VERDICT = "analyst_verdict"
        CHALLENGE = "challenge"

    class LabelClass(models.TextChoices):
        SAFE = "Safe"
        UNWANTED = "Unwanted"
        DANGEROUS = "Dangerous"
        SUSPICIOUS = "Suspicious"
        INCONCLUSIVE = "Inconclusive"

    class Trust(models.TextChoices):
        FOLDER = "folder"
        VERDICT = "verdict"
        PROPOSAL = "proposal"

    class Status(models.TextChoices):
        ACTIVE = "active"
        SUPERSEDED = "superseded"
        FLAGGED = "flagged"

    message_id = models.CharField(max_length=998, db_index=True)
    message_id_hash = models.CharField(max_length=64, db_index=True)
    case = models.ForeignKey(
        "case_handler.Case",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="label_records",
    )
    source = models.CharField(max_length=20, choices=Source.choices)
    source_ref = models.CharField(max_length=255, blank=True)
    label = models.CharField(max_length=64)
    label_class = models.CharField(max_length=20, choices=LabelClass.choices)
    trust = models.CharField(max_length=10, choices=Trust.choices)
    observed_at = models.DateTimeField(default=timezone.now)
    embedding = models.TextField(blank=True)
    preprocessing_version = models.CharField(max_length=32, blank=True)
    campaign_embedding = models.TextField(blank=True)
    embedding_version = models.CharField(max_length=16, blank=True)
    snapshot = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.ACTIVE)
    flag_reason = models.CharField(max_length=64, blank=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_note = models.TextField(blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["message_id_hash", "source", "status"]),
            models.Index(fields=["trust", "status"]),
        ]

    # Ruling D4: the only columns a save() may change; case only from null. QuerySet.update()
    # bypasses this check, so the ledger module updates these columns only.
    MUTABLE = frozenset({"status", "flag_reason", "case_id", "resolved_by_id", "resolved_at", "resolution_note"})

    def save(self, *args, **kwargs):
        if not self._state.adding:
            old = type(self).objects.filter(pk=self.pk).values().first()
            if old is not None:
                changed = {f.attname for f in self._meta.concrete_fields
                           if getattr(self, f.attname) != old[f.attname]}
                if changed - self.MUTABLE or ("case_id" in changed and old["case_id"] is not None):
                    raise ValueError(f"LabelRecord is append-only: {sorted(changed)} cannot change")
        super().save(*args, **kwargs)

    @property
    def trainable(self) -> bool:
        return self.trust == self.Trust.FOLDER and self.status == self.Status.ACTIVE


class LabelSyncState(models.Model):
    """Per-folder IMAP checkpoint."""

    folder = models.CharField(max_length=128, unique=True)
    uidvalidity = models.BigIntegerField(default=0)
    last_uid = models.BigIntegerField(default=0)
    last_run_at = models.DateTimeField(null=True, blank=True)
    skipped = models.IntegerField(default=0)
