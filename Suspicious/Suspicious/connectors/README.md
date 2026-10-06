# 🔌 Connectors — plugin framework

`connectors` is the framework every integration between Suspicious and an external
system (TheHive, MISP, a Watcher domain list, an LLM narration provider, ...) is
built on: a `Connector` base class, a discovery `registry`, an event `dispatch`,
and a delivery pipeline with retries, a circuit breaker, and an audit ledger.

If you're writing a *new* connector, start with
[`docs/connectors.md`](../../../docs/connectors.md) — that's the author-facing guide
(manifest rules, hook contract, packaging). This README documents the framework
itself: what it's made of, how a case event actually reaches a connector, and
what the built-in connectors are.

---

## 📦 Overview

Two ways a connector runs:

- **Event-driven.** A `Case` is created or reaches its terminal (finalised) state;
  `connectors.signals`/`cortex_job.cortex_utils.reconciliation.reconcile_case_core`
  call `connectors.dispatch.emit(event_name, case)`, which fans the event out —
  via Celery, after the triggering transaction commits — to every *enabled*
  connector subscribed to that event.
- **Scheduled.** A connector declares a `Schedule` in its manifest (e.g. Watcher's
  domain-list sync every 300s); `ConnectorsConfig.ready()` registers one Celery
  beat entry per schedule, calling `connector.sync()` on that cadence regardless
  of case activity.

Either path always goes through `connectors.delivery.deliver_now`/`run_sync_now`,
which wraps the actual connector call with a circuit breaker
(`common.http_client.get_breaker`) and records one `ConnectorDelivery` row per
attempt — success, failure, or breaker-skipped — retrying failures up to
`MAX_ATTEMPTS` (3) with exponential backoff. **A connector's own hook code never
writes to the ledger itself** — that bookkeeping is centralized here so every
connector gets it for free and consistently.

---

## 🧩 Directory structure

```
connectors/
├── base.py         # Connector, ConnectorManifest, ConfigField, Schedule,
│                    # HealthStatus, CaseEvent — the public contract
├── registry.py      # discovery (built-ins + "suspicious.connectors" entry points)
├── dispatch.py       # emit(event_name, case) — fan-out to enabled subscribers
├── events.py        # build_case_event(...) — Case -> CaseEvent snapshot
├── delivery.py       # deliver_now / run_sync_now — breaker + ledger + retry logic
├── tasks.py          # deliver_event / run_connector_sync Celery tasks
├── models.py         # ConnectorState, ConnectorDelivery
├── signals.py        # post_save(Case) -> emit("case_created", ...)
├── bootstrap.py       # seeds settings.json connector secrets into Vault at boot
├── apps.py           # registers beat schedules from every manifest's Schedule
└── contrib/          # built-in connectors (one directory per connector)
    ├── misp/
    ├── thehive/
    ├── watcher/
    ├── smtp_notify/
    ├── chromadb/
    ├── ai_narration/
    └── template/      # scaffold to copy when writing a new one
```

---

## 🧱 The contract (`base.py`)

- **`ConnectorManifest`** — `name` (validated slug), `version`, `category`,
  `description`, `config_schema` (tuple of `ConfigField`), `events` (subset of
  `EVENT_CASE_CREATED` / `EVENT_CASE_FINALISED`), `schedules` (tuple of
  `Schedule`), `enabled_by_default`. `.validate()` runs at registration time —
  a connector with an invalid manifest fails to register, it does not take the
  app down.
- **`ConfigField`** — one config key (dotted keys like `instances.primary.api_key`
  describe nesting); `type="secret"` fields get their leaf registered into
  `settings.SECRET_FIELDS` automatically, so they're Vault-overlaid the same way
  every other secret in the app is.
- **`CaseEvent`** — the frozen, versioned (`schema_version`) snapshot a hook
  receives: `event`, `case_id`, `status`, `results`, `final_score`, `confidence`,
  `reporter_email`, `created_at`. A connector needing more than this must
  re-fetch the `Case` by id itself — the payload is deliberately thin so it
  round-trips through Celery/JSON cleanly.
- **`Connector`** (ABC) — subclasses set a class-level `manifest` and implement
  `health_check()` (must never raise) plus whichever of `on_case_created`,
  `on_case_finalised`, `sync` their manifest actually subscribes to.

---

## 🔎 Registry, dispatch, delivery

- **`registry.discover()`** (called once, from `ConnectorsConfig.ready()`) loads
  every path in `connectors.contrib.BUILTIN_CONNECTOR_PATHS`, then anything
  registered under the `suspicious.connectors` Python entry-point group (how a
  third-party package plugs in). A connector that fails to import or fails
  `.validate()` is recorded in `registry.errors` and skipped — never a hard
  startup failure.
- **`dispatch.emit(event_name, case)`** looks up `registry.subscribers(event_name)`,
  filters to connectors with `ConnectorState.enabled=True`, and enqueues one
  `connectors.tasks.deliver_event` Celery task per subscriber — deliberately
  inside `transaction.on_commit(...)`, so a connector never observes
  not-yet-committed case state. Never raises into the calling pipeline.
- **`delivery.deliver_now(connector_name, event_name, payload, attempt)`** does
  the actual work: instantiate the connector (config pulled fresh from
  `settings.config.get_section("integrations.<name>")`), call the hook inside
  `breaker.calling()`, and record a `ConnectorDelivery` row. A
  `pybreaker.CircuitBreakerError` records `STATUS_SKIPPED`; any other exception
  records `STATUS_FAILED` and — below `MAX_ATTEMPTS` — raises
  `RetryableDeliveryError`, which `tasks.deliver_event` turns into a Celery retry
  with `30 * 2**attempt` backoff.
- **`ConnectorState`** (one row per connector, admin-managed) is what
  `enabled=True/False` actually is — seeded from `manifest.enabled_by_default` on
  first read (`delivery.get_state`), overridable per-deployment without a code
  change.

---

## 🏗️ Built-in connectors (`contrib/`)

| Connector | Category | Trigger | Default | Notes |
|---|---|---|---|---|
| `thehive` | Incident Response | `case_finalised` | off | Pushes a TheHive alert |
| `misp` | Threat Intelligence | `case_finalised` | off | Pushes an MISP event |
| `smtp_notify` | Notifications | `case_finalised` | **on** | Emails the reporter the final result. Challenge-workflow notifications are separate and wired directly (`tasp/services/challenge.py`), not through this connector |
| `chromadb` | Maintenance | scheduled (daily) | **on** | Vector-store cleanup, not case-event-driven |
| `watcher` | Threat Intelligence | scheduled (every 300s) | off | Reconciles the allow/deny domain lists against the Watcher service — moved here from `tasp`; see `tasp/README.md` |
| `ai_narration` | AI | `case_finalised` | off | See below — the one connector with an extra, hardcoded data-governance restriction |
| `template` | — | — | — | Not a real connector; copy this directory to start a new one |

### `ai_narration`'s Ollama-only restriction

Every other connector's `config_schema` is the operator's business: point
`thehive` or `misp` at whatever instance you want, no framework-level
restriction. `ai_narration` is deliberately different. It generates a
plain-language case narration via an LLM and can be configured to use a local
Ollama instance *or* an external provider (OpenAI/Anthropic/Gemini) — but only
on its **manual** trigger (`manage.py test_ai_narration`, a human explicitly
choosing to run it against one case). Its **automatic** `on_case_finalised`
hook hardcodes local Ollama and never imports or calls the provider
auto-selection logic (`connectors/contrib/ai_narration/select.py`) at all —
there is no code path from an automatic case-finalisation event to an
external LLM provider. This is a deliberate data-governance decision (real
case content, e.g. a phishing email's own text, must never reach an external
service without a human choosing that specific run) — see
`docs/specs/2026-09-21-ai-narration-event-wiring-design.md` for the full
reasoning. Generated narration is currently observable only via an INFO log
line (`connectors.contrib.ai_narration`); no report/email/UI rendering exists
yet, pending resolution of the same prompt-injection concern for a
reader-facing surface.

---

## 🧪 Testing

```bash
docker exec suspicious bash -c "cd /app/Suspicious && python manage.py test connectors"
```

Framework tests live in `connectors/tests/`; each contrib connector has its own
`connectors/tests/test_contrib_<name>*.py` files alongside the framework ones
(`test_registry.py`, `test_dispatch.py` — covers `delivery.py` too, `test_models.py`,
`test_events.py`, `test_wiring.py`, `test_status.py`).

### Redelivering lost deliveries

A delivery that exhausts its retries (3 attempts, ~100s) or is skipped by an open
circuit breaker is not retried again. Replay them once the target is back:

```bash
manage.py redeliver_connector misp --dry-run          # list affected cases
manage.py redeliver_connector misp --since 2d          # re-emit case_finalised
```

Only cases whose latest ledger row is `failed`/`skipped` (and older than `--min-age`,
default 300s) are re-emitted; connectors deduplicate, so repeating it is safe.

---

## 📄 License

Apache-2.0 (same as the parent project).
