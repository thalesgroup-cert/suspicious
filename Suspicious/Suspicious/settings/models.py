from django.conf import settings
from django.db import models
from django.contrib.auth.hashers import make_password

from domain_process.models import Domain
from hash_process.models import Hash


class Mailbox(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, unique=True)
    username = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=256)
    server = models.CharField(max_length=50)
    port = models.IntegerField()
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if self.password and not str(self.password).startswith("pbkdf2_"):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class EmailFeederState(models.Model):
    is_running = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Email Feeder is {'ON' if self.is_running else 'OFF'}"


class AllowListDomain(models.Model):
    id = models.AutoField(primary_key=True)
    domain = models.ForeignKey(
        Domain,
        on_delete=models.CASCADE,
        related_name="allow_lists",
        null=True,
        blank=True,
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.domain.value if self.domain else f"AllowListDomain #{self.id}"


class WatcherLegitDomain(models.Model):
    id = models.AutoField(primary_key=True)
    watcher_id = models.IntegerField(unique=True, null=True, blank=True)
    domain = models.ForeignKey(
        Domain,
        on_delete=models.CASCADE,
        related_name="legit_lists",
        null=True,
        blank=True,
    )
    status = models.CharField(max_length=100, blank=True, default="")
    remote_last_update = models.DateTimeField(null=True, blank=True)
    raw_payload = models.JSONField(default=dict, blank=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["domain"], name="uniq_watcher_legit_domain"),
        ]

    def __str__(self):
        return self.domain.value if self.domain else f"WatcherLegitDomain #{self.id}"


class DenyListDomain(models.Model):
    id = models.AutoField(primary_key=True)
    domain = models.ForeignKey(
        Domain,
        on_delete=models.CASCADE,
        related_name="deny_lists",
        null=True,
        blank=True,
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.domain.value if self.domain else f"DenyListDomain #{self.id}"


class WatcherMonitoredDomain(models.Model):
    id = models.AutoField(primary_key=True)
    watcher_id = models.IntegerField(unique=True, null=True, blank=True)
    domain = models.ForeignKey(
        Domain,
        on_delete=models.CASCADE,
        related_name="monitored_lists",
        null=True,
        blank=True,
    )
    status = models.CharField(max_length=100, blank=True, default="")
    remote_last_update = models.DateTimeField(null=True, blank=True)
    raw_payload = models.JSONField(default=dict, blank=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["domain"], name="uniq_watcher_monitored_domain"),
        ]

    def __str__(self):
        return self.domain.value if self.domain else f"WatcherMonitoredDomain #{self.id}"


class CampaignDomainAllowList(models.Model):
    id = models.AutoField(primary_key=True)
    domain = models.ForeignKey(
        Domain,
        on_delete=models.CASCADE,
        related_name="campaign_allow_lists",
        null=True,
        blank=True,
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.domain.value if self.domain else f"CampaignDomainAllowList #{self.id}"


class AllowListFile(models.Model):
    id = models.AutoField(primary_key=True)
    linked_file_hash = models.ForeignKey(
        Hash,
        on_delete=models.CASCADE,
        related_name="allow_lists",
        null=True,
        blank=True,
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.linked_file_hash.value if self.linked_file_hash else f"AllowListFile #{self.id}"


class DenyListFile(models.Model):
    id = models.AutoField(primary_key=True)
    linked_file_hash = models.ForeignKey(
        Hash,
        on_delete=models.CASCADE,
        related_name="deny_lists",
        null=True,
        blank=True,
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.linked_file_hash.value if self.linked_file_hash else f"DenyListFile #{self.id}"


class AllowListFiletype(models.Model):
    id = models.AutoField(primary_key=True)
    filetype = models.CharField(max_length=200)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.filetype


class RuntimeConfig(models.Model):
    """Non-secret runtime config seeded from settings.json, editable in admin.

    ``key`` is a dotted settings path (e.g. "integrations.cortex.url").
    ``value`` is JSON so str/int/bool/list/dict round-trip unchanged.
    """

    SCOPE_CHOICES = (("shared", "shared"), ("backend", "backend"), ("feeder", "feeder"))

    scope = models.CharField(max_length=20, choices=SCOPE_CHOICES, default="backend")
    key = models.CharField(max_length=200)
    value = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Runtime config entry"
        verbose_name_plural = "Runtime config"
        constraints = [
            models.UniqueConstraint(fields=["scope", "key"], name="uniq_scope_key"),
        ]

    def __str__(self):
        return self.key

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        from settings.config import invalidate_cache
        invalidate_cache(self.key)

    def delete(self, *args, **kwargs):
        key = self.key
        super().delete(*args, **kwargs)
        from settings.config import invalidate_cache
        invalidate_cache(key)
