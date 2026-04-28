"""
OpenTelemetry initialisation for the Suspicious platform.

Call configure() exactly once from SuspiciousConfig.ready().
No-ops silently when enabled=False so test runs are unaffected.
"""
import logging

logger = logging.getLogger(__name__)


class TraceIdFilter(logging.Filter):
    """
    Logging filter that injects the active OTel trace_id and span_id
    into every log record.

    With active span:    record.trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    Without active span: record.trace_id = "0" * 32
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            from opentelemetry import trace
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
    service_name: str,
    otlp_endpoint: str,
    enabled: bool = True,
) -> None:
    """
    Initialise the TracerProvider and instrument Django, requests, Celery.

    Parameters
    ----------
    service_name:   Resource attribute identifying this service in Tempo.
    otlp_endpoint:  OTLP HTTP collector URL, e.g. "http://tempo:4318".
    enabled:        When False, this function is a no-op.
    """
    if not enabled:
        logger.debug("OTel disabled — skipping instrumentation.")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.django import DjangoInstrumentor
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
        from opentelemetry.instrumentation.celery import CeleryInstrumentor
    except ImportError as exc:
        logger.warning("OpenTelemetry packages not installed — tracing disabled: %s", exc)
        return

    resource = Resource.create({"service.name": service_name})
    exporter = OTLPSpanExporter(endpoint=f"{otlp_endpoint.rstrip('/')}/v1/traces")
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    DjangoInstrumentor().instrument()
    RequestsInstrumentor().instrument()
    CeleryInstrumentor().instrument()

    logger.info(
        "OpenTelemetry initialised: service=%s endpoint=%s",
        service_name, otlp_endpoint,
    )
