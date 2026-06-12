from django.db import models


class ConnectorState(models.Model):
    """Admin-managed runtime state of one discovered connector."""
    name = models.CharField(max_length=100, unique=True)
    enabled = models.BooleanField(default=False)
    last_health_ok = models.BooleanField(null=True, blank=True)
    last_health_detail = models.TextField(blank=True, default="")
    last_health_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({'enabled' if self.enabled else 'disabled'})"


class ConnectorDelivery(models.Model):
    """One attempted hook/sync execution. Ledger powering the deliveries API."""
    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"
    STATUS_SKIPPED = "skipped"
    STATUS_CHOICES = (
        (STATUS_SUCCESS, STATUS_SUCCESS),
        (STATUS_FAILED, STATUS_FAILED),
        (STATUS_SKIPPED, STATUS_SKIPPED),
    )

    connector = models.CharField(max_length=100)
    event = models.CharField(max_length=50)
    case_id = models.IntegerField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    error = models.TextField(blank=True, default="")
    duration_ms = models.IntegerField(default=0)
    attempt = models.IntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["connector", "-created_at"]),
            models.Index(fields=["case_id"]),
        ]
