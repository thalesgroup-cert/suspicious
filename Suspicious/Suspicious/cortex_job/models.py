from django.db import models
from django.utils.translation import gettext_lazy as _
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
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']
        indexes = [
            # Hot path: get_new_reports filters by (type, <fk>_id) and excludes
            # status='Deleted'. One composite per artifact FK lets the optimizer
            # do a single index seek instead of fk-index + status filter.
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
        # Use *_id checks to avoid extra DB lookups when the FK row is not
        # already prefetched. Falls back to the linked object only for the
        # one slot that is populated.
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
    cortex_job_id = models.CharField(max_length=50, db_index=True)
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
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
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
