"""
Custom Prometheus metrics for the Suspicious platform.

Imported by api/apps.py (ready) to register the queue-depth collector.
Individual counters/histograms are imported at call sites in cron tasks
and signals to avoid circular imports.
"""
from prometheus_client import Counter, Gauge, Histogram
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector

# ---------------------------------------------------------------------------
# Business counters
# ---------------------------------------------------------------------------

cases_created_total = Counter(
    "suspicious_cases_created_total",
    "Total number of cases created.",
)

cortex_calls_total = Counter(
    "suspicious_cortex_calls_total",
    "Total Cortex analyzer sync calls.",
)

cortex_errors_total = Counter(
    "suspicious_cortex_errors_total",
    "Total Cortex sync errors by type.",
    ["error_type"],  # circuit_open | network | api
)

# ---------------------------------------------------------------------------
# Histograms
# ---------------------------------------------------------------------------

cortex_sync_duration_seconds = Histogram(
    "suspicious_cortex_sync_duration_seconds",
    "Duration of cortex analyzer sync in seconds.",
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
)

# ---------------------------------------------------------------------------
# Gauges
# ---------------------------------------------------------------------------

email_feeder_last_poll_seconds = Gauge(
    "suspicious_email_feeder_last_poll_timestamp_seconds",
    "Unix timestamp of the last successful email fetch from MinIO.",
)

# ---------------------------------------------------------------------------
# Custom collector — queue depth (queries DB on every scrape)
# ---------------------------------------------------------------------------


class _SubmissionQueueCollector(Collector):
    """Reports submission_queue_depth by status without holding a stale value."""

    def collect(self):
        try:
            from django.db.models import Count
            from submission_queue.models import SubmissionQueue, SubmissionStatus

            counts = dict(
                SubmissionQueue.objects.values_list("status").annotate(n=Count("id"))
            )
            g = GaugeMetricFamily(
                "suspicious_submission_queue_depth",
                "Submission queue depth by status.",
                labels=["status"],
            )
            for status in SubmissionStatus.values:
                g.add_metric([status], counts.get(status, 0))
            yield g
        except Exception:
            # DB unavailable at startup or in tests — yield nothing.
            return


QUEUE_COLLECTOR = _SubmissionQueueCollector()
