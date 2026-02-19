from __future__ import annotations
import hashlib
import secrets
from urllib.parse import urlparse

from django.conf import settings
from django.db import models
from ip_process.models import IP
from url_process.models import URL
from file_process.models import File
from hash_process.models import Hash
from mail_feeder.models import Mail
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
import datetime
from datetime import timedelta

import hashlib

class Status(models.TextChoices):
    """
    Enumeration of possible case statuses.
    """
    TODO = 'To Do', _('To Do')
    ONGOING = 'On Going', _('On Going')
    CHALLENGED = 'Challenged', _('Challenged')
    DONE = 'Done', _('Done')


class Result(models.TextChoices):
    """
    Enumeration of possible case result statuses.
    """
    SAFE = 'Safe', _('Safe')
    INCONCLUSIVE = 'Inconclusive', _('Inconclusive')
    UNCHALLENGED = 'Unchallenged', _('Unchallenged')
    ALLOW_LISTED = 'AllowListed', _('AllowListed')
    FAILURE = 'Failure', _('Failure')
    SUSPICIOUS = 'Suspicious', _('Suspicious')
    DANGEROUS = 'Dangerous', _('Dangerous')


class Case(models.Model):
    """
    Main incident investigation case, storing scores, analyst decisions and AI predictions.
    """
    description = models.TextField()
    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='cases', db_index=True)
    analysis_done = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.TODO, verbose_name='Status', db_index=True)
    results = models.CharField(max_length=20, choices=Result.choices, default=Result.SUSPICIOUS, verbose_name='Results', db_index=True)
    finalScore = models.FloatField(default=0, db_index=True)
    finalConfidence = models.FloatField(default=0, db_index=True)
    score = models.FloatField(default=0, db_index=True)
    confidence = models.FloatField(default=0, db_index=True)
    resultsAI = models.CharField(max_length=20, default="Suspicious", verbose_name='ResultsAI', db_index=True)
    scoreAI = models.FloatField(default=0, db_index=True)
    confidenceAI = models.FloatField(default=0, db_index=True)
    categoryAI = models.CharField(max_length=20, default='Uncategorized', verbose_name='Category AI', db_index=True)
    fileOrMail = models.ForeignKey('CaseHasFileOrMail', on_delete=models.CASCADE, related_name='cases', null=True, blank=True, db_index=True)
    nonFileIocs = models.ForeignKey('CaseHasNonFileIocs', on_delete=models.CASCADE, related_name='cases', null=True, blank=True, db_index=True)
    is_challenged = models.BooleanField(default=False)
    is_challengeable = models.BooleanField(default=True)
    challenged_result = models.CharField(max_length=20, choices=Result.choices, default=Result.UNCHALLENGED, verbose_name='Challenged Result', db_index=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)
    last_update_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='cases_last_update_by', null=True, blank=True, db_index=True)

    class Meta:
        ordering = ['-creation_date']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['results']),
        ]

    def __str__(self):
        """
        Return a zero-padded string of the case ID (e.g., 000123).
        """
        return f"Case #{self.pk:06d}"

    def was_published_recently(self):
        """
        Check if the case was created in the last 24 hours.
        """
        now = timezone.now()
        return now - datetime.timedelta(days=1) <= self.creation_date <= now


class CaseChallengeToken(models.Model):
    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        related_name="challenge_tokens",
        db_index=True,
    )
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    used_at = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["case", "expires_at"], name="cct_case_expires_idx"),
            models.Index(fields=["case", "used_at"], name="cct_case_used_idx"),
        ]

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @classmethod
    def issue_token(cls, case, *, lifetime=None):
        if lifetime is None:
            lifetime_seconds = getattr(settings, "CASE_CHALLENGE_TOKEN_TTL_SECONDS", 86400)
            lifetime = datetime.timedelta(seconds=lifetime_seconds)
        raw_token = secrets.token_urlsafe(32)
        instance = cls.objects.create(
            case=case,
            token_hash=cls.hash_token(raw_token),
            expires_at=timezone.now() + lifetime,
        )
        return raw_token, instance

    @staticmethod
    def build_challenge_url(case_id: int, token: str, api_base: str) -> str:
        base = (api_base or "").rstrip("/")
        if not base:
            return ""
        if base.endswith("/api"):
            base = base[:-4]
        return f"{base}/api/cases/{case_id}/challenge?token={token}"

    @staticmethod
    def normalize_api_base(submissions_url: str) -> str:
        parsed = urlparse(submissions_url or "")
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}"

    def mark_used(self) -> None:
        self.used_at = timezone.now()
        self.save(update_fields=["used_at"])


class CaseHasFileOrMail(models.Model):
    """
    Association model for cases linked to either a file or an email (one-to-one per instance).
    """
    case = models.ForeignKey('Case', on_delete=models.CASCADE, related_name='case_has_file_or_mail', db_index=True)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='case_has_file_or_mail', null=True, blank=True, db_index=True)
    mail = models.ForeignKey(Mail, on_delete=models.CASCADE, related_name='case_has_file_or_mail', null=True, blank=True, db_index=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']

    def get_iocs(self):
        """
        Return the associated file or mail object in a dict.
        """
        return {
            'file': self.file,
            'mail': self.mail,
        }

    def __str__(self):
        file_id = self.file_id or 'N/A'
        mail_id = self.mail_id or 'N/A'
        return f"Case #{self.case_id} - File: {file_id}, Mail: {mail_id}"


class CaseHasNonFileIocs(models.Model):
    """
    Association model for cases linked to non-file IOCs: URLs, IPs, and hashes.
    """
    case = models.ForeignKey('Case', on_delete=models.CASCADE, related_name='case_has_non_file_iocs', db_index=True)
    url = models.ForeignKey(URL, on_delete=models.CASCADE, related_name='case_has_non_file_iocs', null=True, blank=True, db_index=True)
    ip = models.ForeignKey(IP, on_delete=models.CASCADE, related_name='case_has_non_file_iocs', null=True, blank=True, db_index=True)
    hash = models.ForeignKey(Hash, on_delete=models.CASCADE, related_name='case_has_non_file_iocs', null=True, blank=True, db_index=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']

    def get_iocs(self):
        """
        Return the associated URL, IP, or hash as a dict.
        """
        return {
            'url': self.url,
            'ip': self.ip,
            'hash': self.hash,
        }

    def __str__(self):
        parts = []
        if self.url_id:
            parts.append(f"URL: {self.url_id}")
        if self.ip_id:
            parts.append(f"IP: {self.ip_id}")
        if self.hash_id:
            parts.append(f"Hash: {self.hash_id}")
        if not parts:
            parts.append("No IOC")
        return f"Case #{self.case_id} - " + ", ".join(parts)


class FileInCases(models.Model):
    """
    Many-to-many association between files and cases.
    """
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='file_cases', db_index=True)
    case = models.ManyToManyField('Case', related_name='file_cases', blank=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']

    def __str__(self):
        return f"File ID: {self.file_id}"


class HashInCases(models.Model):
    """
    Many-to-many association between hashes and cases.
    """
    hash = models.ForeignKey(Hash, on_delete=models.CASCADE, related_name='hash_cases', db_index=True)
    case = models.ManyToManyField('Case', related_name='hash_cases', blank=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']

    def __str__(self):
        return f"Hash ID: {self.hash_id}"


class UrlInCases(models.Model):
    """
    Many-to-many association between URLs and cases.
    """
    url = models.ForeignKey(URL, on_delete=models.CASCADE, related_name='url_cases', db_index=True)
    case = models.ManyToManyField('Case', related_name='url_cases', blank=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']

    def __str__(self):
        return f"URL ID: {self.url_id}"


class IpInCases(models.Model):
    """
    Many-to-many association between IPs and cases.
    """
    ip = models.ForeignKey(IP, on_delete=models.CASCADE, related_name='ip_cases', db_index=True)
    case = models.ManyToManyField('Case', related_name='ip_cases', blank=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']

    def __str__(self):
        return f"IP ID: {self.ip_id}"


class MailInCases(models.Model):
    """
    Many-to-many association between mails and cases.
    """
    associated_mail = models.ForeignKey(Mail, on_delete=models.CASCADE, related_name='cases_associated_with_mail', db_index=True)
    associated_cases = models.ManyToManyField('Case', related_name='mail_cases', blank=True)
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-creation_date']

    def __str__(self):
        return f"Mail ID: {self.associated_mail_id}"
