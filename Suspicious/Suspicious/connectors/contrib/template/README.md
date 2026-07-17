# suspicious-connector-template

A copy-paste starting point for a third-party [Suspicious](https://github.com/thalesgroup-cert/suspicious)
connector — the plugin mechanism used to push case activity (new
submissions, finalised verdicts) to external tools like ticketing systems,
threat-intel platforms, or chat. The built-in TheHive/MISP/Watcher/SMTP
integrations are themselves connectors built the same way.

**Full contract, delivery guarantees, and the `CaseEvent` schema:**
[`docs/connectors.md`](https://github.com/thalesgroup-cert/suspicious/blob/main/docs/connectors.md)
in the main repo. Read that first — this template is deliberately thin and
assumes you have it open.

## Using this template

1. Copy this whole directory out of the Suspicious repo into its own
   project (a connector is an independent pip package — it doesn't live
   inside Suspicious's codebase).
2. Rename:
   - the package directory `src/suspicious_connector_template/` → your name
   - `name` and the entry-point target in `pyproject.toml`
   - `TemplateConnector` → your class name, everywhere
3. Edit `connector.py`: set a real `manifest` (the `name` slug is what
   matters most — it's your config section, breaker key, and ledger key),
   declare the config fields you actually need, and implement the hooks
   you subscribe to in `manifest.events`. Delete the ones you don't
   (subscribing to an event without implementing its hook just records a
   failed delivery, it doesn't crash anything, but there's no reason to
   leave dead code).
4. Update `tests/test_connector.py` to match — at minimum, keep a test that
   calls `manifest.validate()` so a typo in `name`/`events`/`config_schema`
   fails your CI instead of silently landing your connector in
   `registry.errors` at someone's production startup.

## Local development

`connector.py` imports `connectors.base` — the small, dependency-free
contract module this whole thing is built against, and it isn't on PyPI
(it ships *inside* the Suspicious backend, since that's what actually runs
your connector). For local testing, point `PYTHONPATH` at a checkout of the
main repo's `Suspicious/Suspicious/` directory — `connectors/base.py` has no
Django imports of its own, so this works without installing Django:

```bash
pip install -e .[dev]
PYTHONPATH=/path/to/suspicious/Suspicious/Suspicious pytest
```

## Shipping it

Publish the package however you like (PyPI, a private index, or just a
git URL), then on the Suspicious side:

```text
# Suspicious/requirements-connectors.txt
your-connector-package==1.0.0
```

```bash
cd deployment
make build && make deploy
```

The registry discovers every entry point in the `suspicious.connectors`
group at startup. A connector that fails to import or fails
`ConnectorManifest.validate()` is recorded in `registry.errors` (surfaced
as a warning banner in Settings → Connectors) and skipped — it can't take
the rest of the app down.
