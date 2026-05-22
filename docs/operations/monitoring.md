# Monitoring

OpenTelemetry tracing is optional and disabled by default. Enable the trace
stack with:

```bash
make monitor-up   # start Tempo + Grafana (Grafana on port 3000)
```

Turn tracing on in `settings.json` under
`observability.opentelemetry.enabled`. Traces flow to Tempo and are viewed in
Grafana.
