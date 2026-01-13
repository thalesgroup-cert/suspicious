from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


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

    def __str__(self):
        return f"{self.month} - {self.year}"


class MonthlyCasesSummary(models.Model):
    id = models.AutoField(primary_key=True)

    # Existing high-level fields
    suspicious_cases = models.PositiveIntegerField(default=0)
    inconclusive_cases = models.PositiveIntegerField(default=0)
    failure_cases = models.PositiveIntegerField(default=0)
    dangerous_cases = models.PositiveIntegerField(default=0)
    safe_cases = models.PositiveIntegerField(default=0)
    challenged_cases = models.PositiveIntegerField(default=0)
    allow_listed_cases = models.PositiveIntegerField(default=0)

    # 🆕 New detailed categories
    # Uncategorized
    uncategorized_cases = models.PositiveIntegerField(default=0)
    # Suspicious / Unwanted
    spam_cases = models.PositiveIntegerField(default=0)
    newsletter_cases = models.PositiveIntegerField(default=0)

    # Dangerous
    classic_phishing_cases = models.PositiveIntegerField(default=0)
    clone_cases = models.PositiveIntegerField(default=0)
    blackmail_cases = models.PositiveIntegerField(default=0)
    whaling_cases = models.PositiveIntegerField(default=0)

    # Safe
    internal_cases = models.PositiveIntegerField(default=0)
    external_cases = models.PositiveIntegerField(default=0)

    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.id}"

    def update_case_results(self, case_result):
        """
        Increment counters based on a case result or category.
        """
        # High-level results
        if case_result in {"Safe", "Inconclusive", "Suspicious", "Dangerous", "Failure"}:
            setattr(
                self,
                f"{case_result.lower()}_cases",
                getattr(self, f"{case_result.lower()}_cases") + 1
            )

        # Detailed categories
        detailed_map = {
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

        if case_result in detailed_map:
            setattr(self, detailed_map[case_result], getattr(self, detailed_map[case_result]) + 1)

        self.save()


class MonthlyReporterStats(models.Model):
    id = models.AutoField(primary_key=True)
    new_reporters = models.PositiveIntegerField(default=0)
    total_reporters = models.PositiveIntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)


class TotalCasesStats(models.Model):
    id = models.AutoField(primary_key=True)
    total_cases = models.PositiveIntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)


class UserCasesMonthlyStats(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='user_cases_monthly_stats')

    # High-level
    suspicious_cases = models.PositiveIntegerField(default=0)
    inconclusive_cases = models.PositiveIntegerField(default=0)
    failure_cases = models.PositiveIntegerField(default=0)
    dangerous_cases = models.PositiveIntegerField(default=0)
    safe_cases = models.PositiveIntegerField(default=0)
    challenged_cases = models.PositiveIntegerField(default=0)
    allow_listed_cases = models.PositiveIntegerField(default=0)

    # 🆕 Detailed categories
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

    def __str__(self):
        return f"{self.user.username} - {self.month} - {self.year}"

    def update_case_results(self, case_result):
        # High-level
        if case_result in {"Safe", "Inconclusive", "Suspicious", "Dangerous", "Failure"}:
            setattr(
                self,
                f"{case_result.lower()}_cases",
                getattr(self, f"{case_result.lower()}_cases") + 1
            )

        # Detailed
        detailed_map = {
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

        if case_result in detailed_map:
            setattr(self, detailed_map[case_result], getattr(self, detailed_map[case_result]) + 1)

        self.save()
