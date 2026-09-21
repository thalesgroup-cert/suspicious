from django.db import models
from file_process.models import File
from mail_feeder.models import MailBody, MailHeader
from ip_process.models import IP
from url_process.models import URL
from hash_process.models import Hash
from domain_process.models import Domain
from email_process.models import MailAddress

class Analyzer(models.Model):
    name = models.CharField(max_length=50, unique=True, db_index=True)
    weight = models.FloatField(default=0.2)
    TIER_AUTHORITATIVE = 1
    TIER_STRONG = 2
    TIER_CONTEXTUAL = 3
    TIER_CHOICES = [
        (TIER_AUTHORITATIVE, "Authoritative"),
        (TIER_STRONG, "Strong"),
        (TIER_CONTEXTUAL, "Contextual"),
    ]
    tier = models.PositiveSmallIntegerField(
        choices=TIER_CHOICES, default=TIER_CONTEXTUAL, db_index=True,
        help_text="Fixed trust classification. 1 = authoritative source, 3 = contextual/noisy.",
    )
    analyzer_cortex_id = models.CharField(max_length=50, unique=True, db_index=True)
    is_active = models.BooleanField(default=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']

    def __str__(self):
        return self.name


class AnalyzerReport(models.Model):
    cortex_job_id = models.CharField(max_length=50, db_index=True)
    type = models.CharField(max_length=50, db_index=True)
    status = models.CharField(max_length=50, db_index=True)
    analyzer = models.ForeignKey(Analyzer, on_delete=models.CASCADE, related_name='analyzer_reports')
    url = models.ForeignKey(URL, on_delete=models.CASCADE, related_name='analyzer_reports', null=True, blank=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='analyzer_reports', null=True, blank=True)
    mail = models.ForeignKey(MailAddress, on_delete=models.CASCADE, related_name='analyzer_reports', null=True, blank=True)
    hash = models.ForeignKey(Hash, on_delete=models.CASCADE, related_name='analyzer_reports', null=True, blank=True)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='analyzer_reports', null=True, blank=True)
    ip = models.ForeignKey(IP, on_delete=models.CASCADE, related_name='analyzer_reports', null=True, blank=True)
    mail_body = models.ForeignKey(MailBody, on_delete=models.CASCADE, related_name='analyzer_reports', null=True, blank=True)
    mail_header = models.ForeignKey(MailHeader, on_delete=models.CASCADE, related_name='analyzer_reports', null=True, blank=True)
    level = models.CharField(max_length=50, db_index=True)
    confidence = models.FloatField()
    score = models.FloatField()
    category = models.TextField(null=True, blank=True)
    report_summary = models.JSONField()
    report_taxonomy = models.JSONField()
    report_full = models.JSONField()
    # Structured, display-ready fields extracted from report_full by
    # score_process.scoring.enrichment (VT vendor list, geo/ASN, dates,
    # threat class, filenames). None = not extracted / no extractor / failed.
    enrichment = models.JSONField(null=True, blank=True, default=None)
    # (bucket, key) of the page screenshot captured by a screenshot analyzer
    # (Lookyloo_Screenshot / Urlscan.io_Scan) and stored in MinIO by
    # score_process.scoring.screenshots. Blank = none captured. Mirrors
    # Mail.preview_bucket / Mail.preview_object_key.
    screenshot_bucket = models.CharField(max_length=255, blank=True, default="")
    screenshot_key = models.CharField(max_length=512, blank=True, default="", db_index=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']
        indexes = [
            models.Index(fields=['type', 'status', 'domain']),
            models.Index(fields=['type', 'status', 'url']),
            models.Index(fields=['type', 'status', 'ip']),
            models.Index(fields=['type', 'status', 'hash']),
            models.Index(fields=['type', 'status', 'mail']),
            models.Index(fields=['type', 'status', 'file']),
            models.Index(fields=['type', 'status', 'mail_body']),
            models.Index(fields=['type', 'status', 'mail_header']),
        ]

    def __str__(self):
        if self.url_id:
            display_value = self.url.address
        elif self.hash_id:
            display_value = self.hash.value
        elif self.file_id:
            display_value = self.file.file_path.name
        elif self.ip_id:
            display_value = self.ip.address
        elif self.mail_body_id:
            display_value = self.mail_body.fuzzy_hash
        elif self.mail_header_id:
            display_value = self.mail_header.fuzzy_hash
        elif self.domain_id:
            display_value = self.domain.value
        elif self.mail_id:
            display_value = self.mail.address
        else:
            display_value = str(self.creation_date)
        return f"{self.analyzer.name} - {self.type} Report - {display_value}"

    def set_category(self, categories):
        """Store the report category as a comma-separated string."""
        self.category = ','.join(categories)

    def get_category(self):
        """Return the report categories as a list."""
        return self.category.split(',') if self.category else []


class CaseAnalyzerJob(models.Model):
    """Per-case ledger of dispatched Cortex jobs.

    One row per (case, cortex_job_id). Multiple cases may share the same
    cortex_job_id when a deduplicated artifact (file, URL, hash, etc.) is
    referenced by several cases — that's why this is a junction table and
    not an FK on AnalyzerReport.

    Status mirrors AnalyzerReport.status but is per-case so we can answer
    'which jobs is this case waiting on' without joining.
    """
    STATUS_WAITING = "Waiting"
    STATUS_INPROGRESS = "InProgress"
    STATUS_SUCCESS = "Success"
    STATUS_FAILURE = "Failure"
    STATUS_DELETED = "Deleted"
    STATUS_CHOICES = [
        (STATUS_WAITING, "Waiting"),
        (STATUS_INPROGRESS, "InProgress"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILURE, "Failure"),
        (STATUS_DELETED, "Deleted"),
    ]
    PENDING_STATUSES = (STATUS_WAITING, STATUS_INPROGRESS)

    case = models.ForeignKey(
        "case_handler.Case",
        on_delete=models.CASCADE,
        related_name="analyzer_jobs",
    )
    cortex_job_id = models.CharField(max_length=50)
    analyzer = models.ForeignKey(
        Analyzer, on_delete=models.PROTECT, related_name="case_jobs"
    )
    analyzer_report = models.ForeignKey(
        AnalyzerReport,
        on_delete=models.SET_NULL,
        related_name="case_jobs",
        null=True, blank=True,
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default=STATUS_INPROGRESS
    )
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["case", "cortex_job_id"],
                name="uniq_case_cortexjob",
            ),
        ]
        indexes = [
            models.Index(fields=["cortex_job_id"]),
            models.Index(fields=["case", "status"]),
            models.Index(fields=["status", "created_at"]),
        ]


class DerivedObservable(models.Model):
    """Provenance: an observable that an extractor analyzer surfaced from
    another observable's report, within one case. See
    docs/specs/2026-09-07-derived-observables-design.md."""

    case = models.ForeignKey(
        "case_handler.Case", on_delete=models.CASCADE, related_name="derived_observables"
    )
    source_report = models.ForeignKey(
        AnalyzerReport, on_delete=models.CASCADE, related_name="derived_observables"
    )
    via_analyzer = models.CharField(max_length=64)

    parent_type = models.CharField(max_length=16)   # url|domain|ip|hash|file
    parent_id = models.PositiveIntegerField()
    child_type = models.CharField(max_length=16)    # url|domain|ip|hash|mail
    child_id = models.PositiveIntegerField()
    child_value = models.CharField(max_length=512)

    child_band = models.CharField(max_length=16, blank=True, default="")
    escalation_note = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["source_report", "child_type", "child_id"],
                name="uniq_derived_per_report_child",
            )
        ]
        indexes = [models.Index(fields=["case", "parent_type", "parent_id"])]

    def __str__(self):
        return f"Case #{self.case_id}: {self.parent_type}#{self.parent_id} -> {self.child_type}#{self.child_id} via {self.via_analyzer}"
