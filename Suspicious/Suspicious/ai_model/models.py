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

    message_id = models.CharField(max_length=998)  # looked up through message_id_hash
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

    # Ruling D4: the only columns a save() may change; case only from null.
    # ponytail: a guard on save() only, not a database rule. Not covered: QuerySet.update() and
    # bulk_update() (ai_model.ledger uses update() on these columns only, plus embedding and
    # preprocessing_version in replace_embedding, the re-embed command's write); a new instance
    # given an existing pk (_state.adding is True, so the check is skipped and save() updates the
    # row); raw SQL. The row is read then written without a lock (TOCTOU), so two concurrent saves are each
    # checked against the row as it was. A DB trigger is the upgrade if the ledger gets other writers.
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


class ModelVersion(models.Model):
    """One registered model version. Status changes only through ai_model.registry."""

    class Status(models.TextChoices):
        CANDIDATE = "candidate"
        SHADOW = "shadow"
        ACTIVE = "active"
        PREVIOUS = "previous"
        DISCARDED = "discarded"
        FAILED = "failed"

    class Trigger(models.TextChoices):
        MANUAL = "manual"
        SCHEDULE = "schedule"
        IMPORT = "import"

    version_id = models.CharField(max_length=64, unique=True)
    status = models.CharField(max_length=10, choices=Status.choices, db_index=True)
    # 1 while active, NULL otherwise. MariaDB has no partial unique index, so this unique column is
    # what stops two active versions. Set and cleared only by ai_model.registry.
    active_slot = models.PositiveSmallIntegerField(null=True, unique=True, editable=False)
    # 1 while shadow, NULL otherwise: one shadow at a time, same trick as active_slot.
    shadow_slot = models.PositiveSmallIntegerField(null=True, unique=True, editable=False)
    shadow_since = models.DateTimeField(null=True, blank=True)
    shadow_min_days = models.PositiveSmallIntegerField(default=7)
    recheck = models.JSONField(default=dict)  # {job_id, passed, finished_at} of the gate recheck
    bundle_prefix = models.CharField(max_length=255, blank=True)  # "" for version 0 (no bundle)
    manifest = models.JSONField(default=dict)
    manifest_sha256 = models.CharField(max_length=64, blank=True)  # blank for version 0
    campaign_profile = models.JSONField(default=dict)
    parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="children"
    )
    trigger = models.CharField(max_length=10, choices=Trigger.choices)
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    job_id = models.CharField(max_length=64, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(status="active", active_slot=1, active_slot__isnull=False)
                | (~models.Q(status="active") & models.Q(active_slot__isnull=True)),
                name="ai_model_active_slot_matches_status",
            ),
            models.CheckConstraint(
                condition=models.Q(status="shadow", shadow_slot=1, shadow_slot__isnull=False)
                | (~models.Q(status="shadow") & models.Q(shadow_slot__isnull=True)),
                name="ai_model_shadow_slot_matches_status",
            ),
        ]

    def __str__(self):
        return f"{self.version_id} ({self.status})"


class ModelEvent(models.Model):
    """One row per registry transition."""

    version = models.ForeignKey(ModelVersion, on_delete=models.CASCADE, related_name="events")
    action = models.CharField(max_length=32)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    at = models.DateTimeField(default=timezone.now)
    note = models.TextField(blank=True)


class RetrainJob(models.Model):
    """One /v2/train job (ai_model.retrain). Written before the server is called, so a crash leaves
    a visible job that the next poll or start fails. No URL and no server error text is stored."""

    class State(models.TextChoices):
        RUNNING = "running"
        SUCCEEDED = "succeeded"
        FAILED = "failed"
        CANCELLED = "cancelled"

    job_id = models.CharField(max_length=64, unique=True)
    target_version = models.CharField(max_length=64)  # the candidate's version_id if the job succeeds
    state = models.CharField(max_length=10, choices=State.choices, db_index=True)
    # 1 while running, NULL otherwise: the unique column allows one running job (as active_slot).
    running_slot = models.PositiveSmallIntegerField(null=True, unique=True, editable=False)
    prefix = models.CharField(max_length=255)  # the bundle prefix, ai-models/<version_id>/<job_id>/
    params = models.JSONField(default=dict)  # the /v2/train params: ids, digests, campaign profile
    rows = models.PositiveIntegerField(default=0)
    excluded_rows = models.PositiveIntegerField(default=0)  # trainable rows left out (not re-embedded)
    parent = models.ForeignKey(ModelVersion, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    version = models.ForeignKey(ModelVersion, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    trigger = models.CharField(max_length=10, choices=ModelVersion.Trigger.choices)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    # A class name, or the server's own short `error` filtered by retrain.server_error; never an
    # exception message from Django.
    error = models.CharField(max_length=200, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(state="running", running_slot=1, running_slot__isnull=False)
                | (~models.Q(state="running") & models.Q(running_slot__isnull=True)),
                name="ai_model_running_slot_matches_state",
            )
        ]

    def __str__(self):
        return f"{self.job_id} ({self.state})"


class ShadowResult(models.Model):
    """What the shadow model answered for one case. Never read by the live verdict."""

    class Origin(models.TextChoices):
        LIVE = "live"
        SEED = "seed"

    class Flip(models.TextChoices):
        NONE = "none"
        CHANGED = "changed"
        CRITICAL = "critical"

    case = models.ForeignKey("case_handler.Case", on_delete=models.CASCADE, related_name="shadow_results")
    version = models.ForeignKey(ModelVersion, on_delete=models.CASCADE, related_name="shadow_results")
    origin = models.CharField(max_length=4, choices=Origin.choices, default=Origin.LIVE)
    result = models.CharField(max_length=20, choices=AiAssessment.Result.choices)
    sub_class = models.CharField(max_length=32, blank=True)
    score = models.FloatField()
    confidence = models.FloatField()  # percent, as in Case.confidence_ai
    probabilities = models.JSONField(default=dict)
    tier = models.CharField(max_length=8, blank=True)
    error = models.CharField(max_length=64, blank=True)
    live_result = models.CharField(max_length=20, blank=True)
    would_be_result = models.CharField(max_length=20, blank=True)
    would_be_score = models.FloatField(null=True, blank=True)
    would_be_confidence = models.FloatField(null=True, blank=True)
    would_be_rule = models.CharField(max_length=64, blank=True)
    flip = models.CharField(max_length=8, choices=Flip.choices, default=Flip.NONE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["case", "version"], name="ai_model_shadow_result_case_version")]


class ShadowCampaignEffect(models.Model):
    """What campaign detection would have done for one case with the shadow's classes (Ruling F7)."""

    class Effect(models.TextChoices):
        NO_CHECK = "no_check"
        NONE = "none"
        WOULD_CREATE = "would_create"
        WOULD_JOIN = "would_join"

    case = models.ForeignKey("case_handler.Case", on_delete=models.CASCADE, related_name="shadow_campaign_effects")
    version = models.ForeignKey(ModelVersion, on_delete=models.CASCADE, related_name="campaign_effects")
    effect = models.CharField(max_length=12, choices=Effect.choices)
    member_case_ids = models.JSONField(default=list)
    live_campaign = models.ForeignKey("case_handler.Campaign", null=True, blank=True,
                                      on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["case", "version"],
                                               name="ai_model_shadow_campaign_case_version")]


class ShadowReview(models.Model):
    """An admin's review of one flip or alert-delta item of a shadow version (ai_model.promotion).
    Append-only: a second review adds a row, the latest counts.
    ponytail: a guard on save()/delete() only; QuerySet.update()/delete() and the version's
    cascade bypass it. A DB trigger is the upgrade if reviews get other writers."""

    class Kind(models.TextChoices):
        FLIP = "flip"
        CAMPAIGN = "campaign"

    version = models.ForeignKey(ModelVersion, on_delete=models.CASCADE, related_name="reviews")
    kind = models.CharField(max_length=8, choices=Kind.choices)
    case_id = models.PositiveIntegerField()  # not a FK: the review outlives the case for audit
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                             on_delete=models.SET_NULL, related_name="+")
    note = models.TextField(blank=True)
    at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [models.Index(fields=["version", "kind", "case_id"], name="ai_model_review_item")]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("ShadowReview is append-only")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ShadowReview is append-only")


class ModelVersionStats(models.Model):
    """Daily counters of one model version, attributed through the case's assessment (Ruling F10).
    Recomputed by ai_model.stats; never written by the live path."""

    version = models.ForeignKey(ModelVersion, on_delete=models.CASCADE, related_name="stats")
    day = models.DateField()
    scored = models.PositiveIntegerField(default=0)
    dangerous = models.PositiveIntegerField(default=0)
    campaign_checks = models.PositiveIntegerField(default=0)
    created = models.PositiveIntegerField(default=0)
    joined = models.PositiveIntegerField(default=0)
    alerts = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["version", "day"], name="ai_model_stats_version_day")]
