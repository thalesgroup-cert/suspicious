# Building a connector

Connectors are Suspicious's plugin system for pushing case activity to
external tools — ticketing, threat-intel platforms, chat, SIEM. The
built-in TheHive, MISP, Watcher and SMTP-notify integrations are
themselves connectors (`connectors/contrib/`), and third-party packages
plug in through the same contract without touching Suspicious code.

**Starting your own:** [`examples/suspicious-connector-template/`](https://github.com/thalesgroup-cert/suspicious/tree/main/examples/suspicious-connector-template)
is a complete, working package skeleton (manifest, both hooks, `sync()`,
packaging, and tests) — copy it out and rename rather than starting from
the snippet below.

## Overview

A connector is a Python class deriving from `connectors.base.Connector`
with a declarative `ConnectorManifest`. Connectors come in two tiers:

- **Built-in (contrib)** — shipped in `connectors/contrib/`, always
  discovered, listed in `connectors.contrib.BUILTIN_CONNECTOR_PATHS`.
- **Third-party** — distributed as ordinary pip packages exposing a
  `suspicious.connectors` entry point, installed at image build time via
  `Suspicious/requirements-connectors.txt`.

A connector can react to three kinds of work:

| Hook | Trigger |
|---|---|
| `on_case_created(event)` | a new case enters the pipeline (`case_created`) |
| `on_case_finalised(event)` | scoring finished and a verdict exists (`case_finalised`) |
| `sync()` | a periodic schedule declared in `manifest.schedules`, registered into Celery beat |

plus a mandatory `health_check()` — a cheap connectivity/auth probe that
must never raise (return `HealthStatus(ok=False, detail=...)` instead).
It powers the **Test connection** button and the health chip in
Settings → Connectors.

### Delivery guarantees

Every hook invocation runs on a Celery worker, never inline in the case
pipeline — a broken connector cannot delay or fail a case:

- **Retries** — up to 3 attempts total (1 initial + 2 Celery retries)
  with exponential backoff (30 s · 2^n for events, 60 s · 2^n for syncs).
- **Circuit breaker** — each connector gets its own breaker
  (5 consecutive failures open it; it half-closes after 60 s). While
  open, deliveries are recorded as `skipped` instead of hammering a dead
  endpoint.
- **Delivery ledger** — every attempt writes a `ConnectorDelivery` row
  (event, case, status, error, duration, attempt number), visible per
  connector via the API (`/api/connectors/<name>/deliveries/`).

## Anatomy of a connector

```python
from connectors.base import (
    ConfigField, Connector, ConnectorManifest, HealthStatus,
    EVENT_CASE_FINALISED,
)
import requests


class SlackConnector(Connector):
    manifest = ConnectorManifest(
        name="slack",
        version="1.0.0",
        author="you",
        description="Post finalised case verdicts to a Slack channel.",
        config_schema=(
            ConfigField("webhook_url", "secret", required=True),
            ConfigField("channel", "str", default="#soc"),
        ),
        events=(EVENT_CASE_FINALISED,),
    )

    def health_check(self) -> HealthStatus:
        if not self.config.get("webhook_url"):
            return HealthStatus(ok=False, detail="webhook_url not configured")
        return HealthStatus(ok=True)

    def on_case_finalised(self, event) -> None:
        requests.post(self.config["webhook_url"], json={
            "text": f"Case {event.case_id}: {event.results} "
                    f"(score {event.final_score})",
        }, timeout=10)
```

Manifest rules (enforced by `ConnectorManifest.validate()` at discovery
time — a violation records the connector in `registry.errors` and skips
it, it never crashes startup):

- `name` is a slug: `^[a-z][a-z0-9_]{1,63}$`. It doubles as the config
  section name and the breaker/ledger key.
- `events` may only contain `case_created` / `case_finalised`.
- `config_schema` field types are `str`, `int`, `bool`, `url` or
  `secret`. Keys may be dotted (`instances.primary.api_key`) to describe
  nested config.
- `schedules` are `Schedule(name, interval_seconds)` with a positive
  interval; each one becomes a Celery beat entry calling your `sync()`.
- `enabled_by_default` controls the initial toggle state on first
  discovery; afterwards the admin's choice (stored in `ConnectorState`)
  wins.

Only implement the hooks you subscribe to. Subscribing to an event
without implementing its hook records a failed delivery — it never
propagates into the case pipeline.

## CaseEvent schema

Hooks receive a `CaseEvent`, a frozen snapshot of the case at emission
time. Connectors needing more context must re-fetch the case by id.

| Field | Type | Meaning |
|---|---|---|
| `event` | `str` | `case_created` or `case_finalised` |
| `case_id` | `int` | primary key of the case |
| `status` | `str` | case status at emission time |
| `results` | `str` | verdict (Safe / Inconclusive / Suspicious / Dangerous) |
| `final_score` | `float \| None` | aggregated score, `None` until finalised |
| `confidence` | `float \| None` | classifier confidence, `None` until finalised |
| `reporter_email` | `str` | address of the reporting user |
| `created_at` | `str` | case creation time, ISO-8601 |
| `schema_version` | `int` | currently `1` |

**Compatibility promise:** within a major `schema_version`, changes are
additive only — existing fields keep their name, type and meaning, new
fields may appear. `CaseEvent.from_dict` rejects payloads with a
different major version, so a connector built against version 1 either
receives a payload it understands or a recorded failure — never a
silently reinterpreted one.

## Packaging a third-party connector

Expose the class through the `suspicious.connectors` entry-point group
in your package's `pyproject.toml`:

```toml
[project]
name = "suspicious-slack-connector"
version = "1.0.0"
dependencies = ["requests"]

[project.entry-points."suspicious.connectors"]
slack = "suspicious_slack:SlackConnector"
```

Install it into the backend image by adding one line to
`Suspicious/requirements-connectors.txt`:

```text
suspicious-slack-connector==1.0.0
```

then rebuild and roll out:

```bash
cd deployment
make build && make deploy
```

On startup the registry loads every entry point in the group. An entry
point that fails to import (missing dependency, bad manifest) is
isolated: it lands in `registry.errors`, is surfaced as a warning banner
in Settings → Connectors, and does not affect other connectors.

## Configuration

Each connector owns the `integrations.<name>` config section; the
fields declared in `config_schema` are registered with the runtime
config system automatically.

- **Non-secret fields** are editable from Settings → Connectors (the
  form is generated from the schema) or via
  `PUT /api/connectors/<name>/config/`.
- **`secret` fields** are write-rejected and read-masked through the
  API. Manage them in Vault (production) or `settings.json` (dev) —
  they are overlaid at read time and never stored in the database.

Enable/disable with the toggle in Settings → Connectors (or
`PATCH /api/connectors/<name>/` with `{"enabled": false}`), and verify
connectivity with **Test connection**, which calls your
`health_check()`.

## Operational behavior

- **Ledger** — every attempt is a `ConnectorDelivery` row. `success`
  means your hook returned; `failed` means it raised (the message is
  stored, truncated to 5000 chars); `skipped` means the circuit breaker
  was open and the call was never made. Skipped deliveries are not
  retried — the case pipeline has long moved on; re-sync from the
  external side or wait for the next event.
- **Retries** — a raising hook is retried while `attempt <
  MAX_ATTEMPTS` (3). Each attempt gets its own ledger row.
- **Idempotency is your job** — `case_finalised` can fire more than
  once for the same case (re-finalisation after late analyzer results;
  the same was true of the legacy integrations this framework
  replaces). Use `event.case_id` for dedup or make the downstream write
  idempotent (e.g. upsert by case id).
- **Disabled connectors** receive nothing: events are not enqueued for
  them and scheduled syncs return immediately.
