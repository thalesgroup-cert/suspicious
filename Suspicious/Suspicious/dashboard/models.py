from django.conf import settings
from django.db import models


class CaseResultCountsMixin:
    """Increment per-result and per-category case counters on a stats model.

    Shared by the monthly stats models, which all carry the same
    ``<result>_cases`` / ``<category>_cases`` integer columns.
    """

    _DETAILED_CATEGORIES = {
        "Uncategorized": "uncategorized_cases",
        "Spam": "spam_cases",
        "Newsletter": "newsletter_cases",
        "Classic_phishing": "classic_phishing_cases",
        "Clone": "clone_cases",
        "Blackmail": "blackmail_cases",
        "Whaling": "whaling_cases",
        "Internal": "internal_cases",
        "External": "external_cases",
    }

    def update_case_results(self, case_result):
        if case_result in {"Safe", "Inconclusive", "Suspicious", "Dangerous", "Failure"}:
            field = f"{case_result.lower()}_cases"
            setattr(self, field, getattr(self, field) + 1)

        category_field = self._DETAILED_CATEGORIES.get(case_result)
        if category_field:
            setattr(self, category_field, getattr(self, category_field) + 1)

        self.save()


class Kpi(models.Model):
    id = models.AutoField(primary_key=True)
    month = models.CharField(max_length=200)
    year = models.CharField(max_length=200)
    monthly_cases_summary = models.ForeignKey(
        'MonthlyCasesSummary', on_delete=models.CASCADE, related_name='kpis', null=True, blank=True
    )
    monthly_reporter_stats = models.ForeignKey(
        'MonthlyReporterStats', on_delete=models.CASCADE, related_name='kpis', null=True, blank=True
    )
    total_cases_stats = models.ForeignKey(
        'TotalCasesStats', on_delete=models.CASCADE, related_name='kpis', null=True, blank=True
    )
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["year", "month"], name="kpi_year_month_idx"),
        ]

    def __str__(self):
        return f"{self.month} - {self.year}"


class MonthlyCasesSummary(CaseResultCountsMixin, models.Model):
    id = models.AutoField(primary_key=True)

    suspicious_cases = models.PositiveIntegerField(default=0)
    inconclusive_cases = models.PositiveIntegerField(default=0)
    failure_cases = models.PositiveIntegerField(default=0)
    dangerous_cases = models.PositiveIntegerField(default=0)
    safe_cases = models.PositiveIntegerField(default=0)
    challenged_cases = models.PositiveIntegerField(default=0)
    allow_listed_cases = models.PositiveIntegerField(default=0)

    uncategorized_cases = models.PositiveIntegerField(default=0)
    spam_cases = models.PositiveIntegerField(default=0)
    newsletter_cases = models.PositiveIntegerField(default=0)

    classic_phishing_cases = models.PositiveIntegerField(default=0)
    clone_cases = models.PositiveIntegerField(default=0)
    blackmail_cases = models.PositiveIntegerField(default=0)
    whaling_cases = models.PositiveIntegerField(default=0)

    internal_cases = models.PositiveIntegerField(default=0)
    external_cases = models.PositiveIntegerField(default=0)

    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["creation_date"], name="mcs_creation_idx"),
        ]

    def __str__(self):
        return f"{self.id}"


class MonthlyReporterStats(models.Model):
    id = models.AutoField(primary_key=True)
    new_reporters = models.PositiveIntegerField(default=0)
    total_reporters = models.PositiveIntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["creation_date"], name="mrs_creation_idx"),
        ]

    def __str__(self):
        return str(self.id)


class TotalCasesStats(models.Model):
    id = models.AutoField(primary_key=True)
    total_cases = models.PositiveIntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["creation_date"], name="tcs_creation_idx"),
        ]

    def __str__(self):
        return str(self.id)


class UserCasesMonthlyStats(CaseResultCountsMixin, models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='user_cases_monthly_stats')

    suspicious_cases = models.PositiveIntegerField(default=0)
    inconclusive_cases = models.PositiveIntegerField(default=0)
    failure_cases = models.PositiveIntegerField(default=0)
    dangerous_cases = models.PositiveIntegerField(default=0)
    safe_cases = models.PositiveIntegerField(default=0)
    challenged_cases = models.PositiveIntegerField(default=0)
    allow_listed_cases = models.PositiveIntegerField(default=0)

    uncategorized_cases = models.PositiveIntegerField(default=0)
    spam_cases = models.PositiveIntegerField(default=0)
    newsletter_cases = models.PositiveIntegerField(default=0)
    classic_phishing_cases = models.PositiveIntegerField(default=0)
    clone_cases = models.PositiveIntegerField(default=0)
    blackmail_cases = models.PositiveIntegerField(default=0)
    whaling_cases = models.PositiveIntegerField(default=0)
    internal_cases = models.PositiveIntegerField(default=0)
    external_cases = models.PositiveIntegerField(default=0)

    total_cases = models.PositiveIntegerField(default=0)
    month = models.CharField(max_length=200)
    year = models.CharField(max_length=200)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["year", "month"], name="ucms_year_month_idx"),
            models.Index(fields=["year", "month", "user"], name="ucms_ymu_idx"),
            models.Index(fields=["user", "year", "month"], name="ucms_uym_idx"),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.month} - {self.year}"


class DashboardSnapshot(models.Model):
    """Pre-materialised dashboard payload for a given month/year."""
    month = models.PositiveSmallIntegerField()
    year = models.PositiveSmallIntegerField()
    payload = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("month", "year")
        indexes = [
            models.Index(fields=["year", "month"], name="snapshot_ym_idx"),
        ]

    def __str__(self):
        return f"DashboardSnapshot {self.year}-{self.month:02d}"


class GroupMonthlyStats(models.Model):
    group_name = models.CharField(max_length=200)
    month = models.CharField(max_length=200)
    year = models.CharField(max_length=200)
    total_cases = models.PositiveIntegerField(default=0)

    suspicious_cases = models.PositiveIntegerField(default=0)
    inconclusive_cases = models.PositiveIntegerField(default=0)
    failure_cases = models.PositiveIntegerField(default=0)
    dangerous_cases = models.PositiveIntegerField(default=0)
    safe_cases = models.PositiveIntegerField(default=0)
    challenged_cases = models.PositiveIntegerField(default=0)
    allow_listed_cases = models.PositiveIntegerField(default=0)

    uncategorized_cases = models.PositiveIntegerField(default=0)
    spam_cases = models.PositiveIntegerField(default=0)
    newsletter_cases = models.PositiveIntegerField(default=0)
    classic_phishing_cases = models.PositiveIntegerField(default=0)
    clone_cases = models.PositiveIntegerField(default=0)
    blackmail_cases = models.PositiveIntegerField(default=0)
    whaling_cases = models.PositiveIntegerField(default=0)
    internal_cases = models.PositiveIntegerField(default=0)
    external_cases = models.PositiveIntegerField(default=0)

    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["year", "month"], name="gms_year_month_idx"),
            models.Index(fields=["year", "month", "group_name"], name="gms_ymg_idx"),
        ]

    def __str__(self):
        return f"{self.group_name} - {self.month} - {self.year}"