from django.db import models


class AiAssessment(models.Model):
    """The full AI result for one case (one row per case, upserted)."""

    class Result(models.TextChoices):
        SAFE = "SAFE"
        UNWANTED = "UNWANTED"
        DANGEROUS = "DANGEROUS"
        INCONCLUSIVE = "INCONCLUSIVE"

    case = models.OneToOneField(
        "case_handler.Case", on_delete=models.CASCADE, related_name="ai_assessment"
    )
    model_version = models.CharField(max_length=32)
    result = models.CharField(max_length=20, choices=Result.choices)
    sub_class = models.CharField(max_length=32, blank=True)
    score = models.FloatField()
    confidence = models.FloatField()  # percent, as in Case.confidence_ai
    probabilities = models.JSONField(default=dict)
    sub_probabilities = models.JSONField(default=dict)
    tier = models.CharField(max_length=8, blank=True)
    contributing_phrases = models.JSONField(default=list)
    similar_cases = models.JSONField(default=list)
    campaign_embedding = models.TextField(blank=True)
    embedding_version = models.CharField(max_length=16, default="cmp-e1")
    latency_ms = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
