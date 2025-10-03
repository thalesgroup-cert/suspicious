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
        indexes = [
            models.Index(fields=['analyzer_cortex_id']),
        ]

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
            models.Index(fields=['cortex_job_id']),
            models.Index(fields=['type']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        # Selects the first available field for display.
        if self.url:
            display_value = self.url.address
        elif self.hash:
            display_value = self.hash.value
        elif self.file:
            display_value = self.file.file_path.name
        elif self.ip:
            display_value = self.ip.address
        elif self.mail_body:
            display_value = self.mail_body.fuzzy_hash
        elif self.mail_header:
            display_value = self.mail_header.fuzzy_hash
        else:
            display_value = str(self.creation_date)
        return f"{self.analyzer.name} - {self.type} Report - {display_value}"

    def set_category(self, categories):
        """Store the report category as a comma-separated string."""
        self.category = ','.join(categories)

    def get_category(self):
        """Return the report categories as a list."""
        return self.category.split(',') if self.category else []
