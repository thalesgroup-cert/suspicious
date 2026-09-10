"""Dispatch an AnalyzerReport to its screenshot extractor and persist the PNG."""
from __future__ import annotations

import io
import logging
from typing import Optional

from django.conf import settings

from cortex_job.cortex_utils.report_target import analyzer_report_target_value
from common.clients import ensure_bucket, get_s3_client
from score_process.scoring.screenshots import lookyloo, urlscan

logger = logging.getLogger(__name__)

# analyzer.name (lowercased) substring -> module exposing extract(report_full, data_type, value).
# Resolve module.extract at call time so tests can patch registry.<mod>.extract.
_EXTRACTORS = (
    ("lookyloo", lookyloo),
    ("urlscan", urlscan),
)

_DEFAULT_BUCKET = "analyzer-screenshots"


def capture(report) -> Optional[bytes]:
    name = (getattr(getattr(report, "analyzer", None), "name", "") or "").lower()
    for key, mod in _EXTRACTORS:
        if key in name:
            try:
                value = analyzer_report_target_value(report)
                return mod.extract(report.report_full, report.type, value)
            except Exception as exc:  # noqa: BLE001
                logger.warning("screenshot extract for %s failed: %s", name, exc, exc_info=True)
                return None
    return None


def store(report, png: bytes) -> None:
    client = get_s3_client()
    bucket = getattr(settings, "SCREENSHOT_BUCKET", _DEFAULT_BUCKET)
    try:
        ensure_bucket(client, bucket)
    except Exception as exc:  # noqa: BLE001
        # Mirrors eml2png_renderer._ensure_bucket: a service account that can
        # put/get a pre-created bucket but not bucket_exists/ListAllMyBuckets
        # must still reach put_object below.
        logger.warning("ensure_bucket(%s) failed (continuing): %s", bucket, exc)
    key = f"report-{report.id}.png"
    client.put_object(bucket, key, io.BytesIO(png), length=len(png), content_type="image/png")
    report.screenshot_bucket = bucket
    report.screenshot_key = key
    report.save(update_fields=["screenshot_bucket", "screenshot_key"])
