# Monitoring

OpenTelemetry tracing is optional and disabled by default. (The older
`make monitor-up` Prometheus/Grafana target has been removed.)

Enable tracing in two steps:

1. Set `observability.opentelemetry.enabled` to `true` in `settings.json`. This
   turns on the OpenTelemetry exporter for the `suspicious`, `suspicious_celery`,
   and `feeder` services.
2. Start the Tempo + Grafana stack from `deployment/docker/monitoring/`
   (Tempo config in `tempo.yaml`, Grafana under `grafana/`). Grafana serves on
   port 3000.

Traces flow to Tempo and are viewed in Grafana.
