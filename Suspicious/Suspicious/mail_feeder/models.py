from django.conf import settings
from django.db import models
from hash_process.models import Hash
from url_process.models import URL
from ip_process.models import IP
from domain_process.models import Domain
from email_process.models import MailAddress
from file_process.models import File
from django.utils.translation import gettext_lazy as _

class Mail(models.Model):
    subject = models.CharField(max_length=255, db_index=True)
    reportedBy = models.CharField(max_length=255, db_index=True)
    mail_header = models.ForeignKey(
        'MailHeader', on_delete=models.CASCADE, related_name='mails',
        null=True, blank=True, db_index=True
    )
    mail_body = models.ForeignKey(
        'MailBody', on_delete=models.CASCADE, related_name='mails',
        null=True, blank=True, db_index=True
    )
    date = models.DateTimeField(db_index=True)
    mail_from = models.CharField(max_length=255, db_index=True, blank=True)
    to = models.CharField(max_length=255, db_index=True)
    cc = models.CharField(max_length=255, blank=True)
    bcc = models.CharField(max_length=255, blank=True)
    mail_id = models.CharField(max_length=255, db_index=True)
    times_sent = models.PositiveIntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-date']
        indexes = [
            models.Index(fields=['mail_id']),
            models.Index(fields=['date']),
        ]

    def __str__(self):
        return f"Mail ID: {self.pk} - Subject: {self.subject[:50]}"


class MailHeader(models.Model):
    header_score = models.FloatField(default=5)
    header_confidence = models.FloatField(default=0)
    header_level = models.CharField(max_length=20, default='info')
    header_value = models.TextField()
    fuzzy_hash = models.TextField()
    times_sent = models.PositiveIntegerField(default=0)
    other_values = models.TextField(blank=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']
        indexes = [
            models.Index(fields=['fuzzy_hash']),
        ]

    def __str__(self):
        return f"Header ID: {self.pk} - Hash: {self.fuzzy_hash[:20]}"


class MailBody(models.Model):
    body_score = models.FloatField(default=5)
    body_confidence = models.FloatField(default=0)
    body_level = models.CharField(max_length=20, default='info')
    body_value = models.TextField()
    fuzzy_hash = models.TextField()
    times_sent = models.PositiveIntegerField(default=0)
    other_values = models.TextField(blank=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']
        indexes = [
            models.Index(fields=['fuzzy_hash']),
        ]

    def __str__(self):
        return f"Body ID: {self.pk} - Hash: {self.fuzzy_hash[:20]}"


class MailArtifact(models.Model):
    TYPE_CHOICES = [
        ('URL', 'URL'),
        ('IP', 'IP'),
        ('Hash', 'Hash'),
        ('Domain', 'Domain'),
        ('MailAddress', 'MailAddress'),
    ]
    mail = models.ForeignKey(
        Mail, on_delete=models.CASCADE, related_name='mail_artifacts', db_index=True, null=True, blank=True
    )
    artifact_score = models.FloatField(default=5)
    artifact_confidence = models.FloatField(default=0)
    artifact_level = models.CharField(max_length=20, default='info')
    artifact_type = models.CharField(max_length=20, choices=TYPE_CHOICES, db_index=True)
    artifactIsIp = models.ForeignKey(
        'ArtifactIsIp', on_delete=models.CASCADE,
        related_name='mail_artifacts', null=True, blank=True
    )
    artifactIsUrl = models.ForeignKey(
        'ArtifactIsUrl', on_delete=models.CASCADE,
        related_name='mail_artifacts', null=True, blank=True
    )
    artifactIsHash = models.ForeignKey(
        'ArtifactIsHash', on_delete=models.CASCADE,
        related_name='mail_artifacts', null=True, blank=True
    )
    artifactIsDomain = models.ForeignKey(
        'ArtifactIsDomain', on_delete=models.CASCADE,
        related_name='mail_artifacts', null=True, blank=True
    )
    artifactIsMailAddress = models.ForeignKey(
        'ArtifactIsMailAddress', on_delete=models.CASCADE,
        related_name='mail_artifacts', null=True, blank=True
    )
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']
        indexes = [
            models.Index(fields=['artifact_type']),
        ]

    def __str__(self):
        return f"{self.artifact_type} - Artifact ID: {self.pk}"


class ArtifactIsIp(models.Model):
    ip = models.ForeignKey(IP, on_delete=models.CASCADE, related_name='ip_artifacts', db_index=True)
    artifact = models.ForeignKey(
        'MailArtifact', on_delete=models.CASCADE, related_name='ip_artifacts', db_index=True
    )
    times_sent = models.IntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']
        indexes = [
            models.Index(fields=['times_sent']),
        ]

    def __str__(self):
        return f"ArtifactIsIp ID: {self.pk} - IP ID: {self.ip_id} - Artifact ID: {self.artifact_id}"

class ArtifactIsUrl(models.Model):
    url = models.ForeignKey(URL, on_delete=models.CASCADE, related_name='url_artifacts', db_index=True)
    artifact = models.ForeignKey(
        'MailArtifact', on_delete=models.CASCADE, related_name='url_artifacts', db_index=True
    )
    times_sent = models.IntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']
        indexes = [
            models.Index(fields=['times_sent']),
        ]

    def __str__(self):
        return f"ArtifactIsUrl ID: {self.pk} - URL ID: {self.url_id} - Artifact ID: {self.artifact_id}"



class ArtifactIsHash(models.Model):
    hash = models.ForeignKey(Hash, on_delete=models.CASCADE, related_name='hash_artifacts', db_index=True)
    artifact = models.ForeignKey(
        'MailArtifact', on_delete=models.CASCADE, related_name='hash_artifacts', db_index=True
    )
    times_sent = models.IntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']
        indexes = [
            models.Index(fields=['times_sent']),
        ]

    def __str__(self):
        return f"ArtifactIsHash ID: {self.pk} - Hash ID: {self.hash_id} - Artifact ID: {self.artifact_id}"



class ArtifactIsDomain(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='domain_artifacts', db_index=True)
    artifact = models.ForeignKey(
        'MailArtifact', on_delete=models.CASCADE, related_name='domain_artifacts', db_index=True
    )
    times_sent = models.IntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']
        indexes = [
            models.Index(fields=['times_sent']),
        ]

    def __str__(self):
        return f"ArtifactIsDomain ID: {self.pk} - Domain ID: {self.domain_id} - Artifact ID: {self.artifact_id}"



class ArtifactIsMailAddress(models.Model):
    mail_address = models.ForeignKey(
        MailAddress, on_delete=models.CASCADE, related_name='mail_address_artifacts', db_index=True
    )
    artifact = models.ForeignKey(
        'MailArtifact', on_delete=models.CASCADE, related_name='mail_address_artifacts', db_index=True
    )
    times_sent = models.IntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']
        indexes = [
            models.Index(fields=['times_sent']),
        ]

    def __str__(self):
        return f"ArtifactIsMailAddress ID: {self.pk} - MailAddress ID: {self.mail_address_id} - Artifact ID: {self.artifact_id}"


class MailArchive(models.Model):
    mail = models.ForeignKey(
        Mail, on_delete=models.CASCADE, related_name='mail_archive', db_index=True
    )
    archive = models.ForeignKey(
        File, on_delete=models.CASCADE, related_name='mail_archive',
        null=True, blank=True, db_index=True
    )
    bucket_name = models.CharField(max_length=255, db_index=True, blank=True)
    def __str__(self):
        return f"Mail ID: {self.mail_id} - Archive ID: {self.archive_id or 'None'}"



class MailAttachment(models.Model):
    mail = models.ForeignKey(
        Mail, on_delete=models.CASCADE, related_name='mail_attachments', db_index=True, null=True, blank=True
    )
    attachment_score = models.FloatField(default=5)
    attachment_confidence = models.FloatField(default=0)
    attachment_level = models.CharField(max_length=20, default='info')
    att_hash_score = models.FloatField(default=5)
    att_hash_confidence = models.FloatField(default=0)
    att_hash_level = models.CharField(max_length=20, default='info')
    file = models.ForeignKey(
        File, on_delete=models.CASCADE, related_name='mail_attachments',
        null=True, blank=True, db_index=True
    )
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']

    def __str__(self):
        return f"Attachment ID: {self.pk} - File ID: {self.file_id or 'None'}"



class MailInfo(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='mail_info', db_index=True
    )
    mail = models.ForeignKey(
        Mail, on_delete=models.CASCADE, related_name='mail_info', db_index=True
    )
    is_received = models.BooleanField(default=False)
    user_reception_informed = models.BooleanField(default=False)
    is_analyzed = models.BooleanField(default=False)
    user_analysis_informed = models.BooleanField(default=False)
    is_phishing = models.BooleanField(default=False)
    user_phishing_informed = models.BooleanField(default=False)
    is_dangerous = models.BooleanField(default=False)
    user_dangerous_informed = models.BooleanField(default=False)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']

    def __str__(self):
        return f"MailInfo ID: {self.pk} - Mail ID: {self.mail_id} - User ID: {self.user_id}"



class MailAnalyzed(models.Model):
    mail = models.ForeignKey(
        Mail, on_delete=models.CASCADE, related_name='mail_analyzed', db_index=True
    )
    is_phishing = models.BooleanField(default=False)
    is_dangerous = models.BooleanField(default=False)
    is_legitimate = models.BooleanField(default=False)
    is_spam = models.BooleanField(default=False)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']

    def __str__(self):
        return f"MailAnalyzed ID: {self.pk} - Mail ID: {self.mail_id}"

