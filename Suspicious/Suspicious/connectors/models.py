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


class ConnectorLink(models.Model):
    """The object a connector created in the remote system for a case (an XSOAR
    incident id, ...). One per (connector, case): lets a connector tell that it
    already pushed a case, so a repeated ``case_finalised`` does not push twice.
    A connector writes the row in the same transaction as the remote call, so a
    failed push leaves no row and the framework's retry starts clean."""
    connector = models.CharField(max_length=100)
    case_id = models.IntegerField()
    remote_id = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["connector", "case_id"], name="connector_link_unique"),
        ]

    def __str__(self):
        return f"{self.connector}: case {self.case_id} -> {self.remote_id or '(pending)'}"
