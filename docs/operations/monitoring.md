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

## Web request timing (gunicorn)

Gunicorn's access log ends every line with the request duration in microseconds
(`%(D)s`), so slow endpoints show up without an APM tool. Summarise the slowest
endpoints by total time, with median, 95th percentile and maximum:

```bash
docker logs suspicious 2>&1 | python3 scripts/slow_endpoints.py --top 15
```

At start-up each worker also logs `worker <pid> warmed up in <seconds>`: it loads
the whole URL configuration before it takes its first request, so no user pays that
cost (about 1.5 s) when a worker restarts. A line `warm-up failed; first request
will be slow` means the warm-up raised an error; the worker still serves requests.

For slow database queries, switch the slow query log on for a while (needs the
database root account; it resets when MariaDB restarts):

```sql
SET GLOBAL slow_query_log = 1;
SET GLOBAL long_query_time = 1;
```

Then read the log inside the database container (`/var/lib/mysql/<container id>-slow.log`)
and switch it off again with `SET GLOBAL slow_query_log = 0; SET GLOBAL long_query_time = 10;`.
