"""
OpenTelemetry initialisation + TraceIdFilter for the email-feeder.

Mirrors `Suspicious/Suspicious/suspicious/otel.py` so trace context is
consistent across services in Tempo.

`configure()` is a no-op when:
- opentelemetry is not installed (we fall back to plain logging)
- `enabled=False` (set via OTEL_ENABLED env var)

Closes audit O5 (docs/superpowers/specs/2026-05-06-audit/observability.md).
"""
from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Hoist `trace` to module scope so tests can patch it directly. None
# when opentelemetry is not installed; the filter handles that branch.
try:
    from opentelemetry import trace  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover — import-time only
    trace = None  # type: ignore[assignment]


class TraceIdFilter(logging.Filter):
    """Inject the active OTel trace_id / span_id onto every record.

    With active span:    record.trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    Without active span: record.trace_id = "0" * 32
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if trace is None:
                raise RuntimeError("opentelemetry not installed")
            span = trace.get_current_span()
            ctx = span.get_span_context()
            if ctx.is_valid:
                record.trace_id = format(ctx.trace_id, "032x")
                record.span_id = format(ctx.span_id, "016x")
            else:
                record.trace_id = "0" * 32
                record.span_id = "0" * 16
        except Exception:
            record.trace_id = "0" * 32
            record.span_id = "0" * 16
        return True


def configure(
    service_name: str = "email-feeder",
    otlp_endpoint: Optional[str] = None,
    enabled: bool = True,
) -> None:
    """Initialise the OTel tracer + auto-instrumentation for `requests`.

    Best-effort: any import / init failure is swallowed and logged at
    DEBUG. The feeder must boot even when the OTel collector is down.
    """
    if not enabled:
        logger.debug("OTel disabled by configure(enabled=False)")
        return

    otlp_endpoint = otlp_endpoint or os.environ.get(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://tempo:4318"
    )

    try:
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
    except ImportError as exc:
        logger.debug("OTel SDK not installed (%s); skipping configure()", exc)
        return

    try:
        provider = TracerProvider(
            resource=Resource.create({SERVICE_NAME: service_name})
        )
        exporter = OTLPSpanExporter(endpoint=f"{otlp_endpoint.rstrip('/')}/v1/traces")
        provider.add_span_processor(BatchSpanProcessor(exporter))

        # Only set the global provider once — Python tests sometimes
        # re-import this module and we don't want to leak processors.
        if trace is not None and getattr(trace, "_TRACER_PROVIDER", None) is None:
            trace.set_tracer_provider(provider)

        # Auto-instrument outbound requests so MinIO + future Django
        # API calls propagate W3C traceparent headers automatically.
        try:
            from opentelemetry.instrumentation.requests import (
                RequestsInstrumentor,
            )
            RequestsInstrumentor().instrument()
        except Exception as exc:  # pragma: no cover — optional
            logger.debug("requests instrumentation skipped: %s", exc)

        logger.info(
            "OTel configured: service=%s endpoint=%s", service_name, otlp_endpoint
        )
    except Exception:
        logger.warning("OTel configure failed; continuing without tracing", exc_info=True)
