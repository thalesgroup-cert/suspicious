# AI Narration Connector: Design

## Context

The verdict-narration spike (`docs/specs/2026-09-11-verdict-narration-spike-design.md`)
proved prompting a model — local or otherwise — is good enough to skip training,
using a deterministic verdict-lock and synthetic fixtures via a one-off
management command hardcoded to a local Ollama server.

This spec turns that into a properly activatable, provider-configurable
capability, reusing the platform's existing `connectors` app rather than
inventing new plumbing: an admin-toggled connector (off by default, does
nothing unless enabled), auto-detecting a provider (a configured external
API key wins; otherwise it falls back to local Ollama), supporting OpenAI,
Anthropic, and Gemini as named external providers alongside Ollama.

This spec deliberately stays a **connector-architecture test**, not the
production integration: it proves activation, provider selection, real-case
adaptation, generation, and validation work end-to-end, with results recorded
to the connector delivery ledger — not wired to any user-facing surface, and
not (yet) triggered automatically on real cases.

## Goals

- Reuse the existing `connectors` framework (`ConnectorState.enabled`,
  `config_schema` → Vault-backed secrets, `ConnectorDelivery` ledger,
  `health_check`) instead of building new activation/config/audit plumbing.
- Auto-detect the provider: any external provider (OpenAI, Anthropic, Gemini)
  with an API key configured wins, in a fixed priority order; otherwise fall
  back to local Ollama. Zero config still does something, as long as Ollama
  is reachable.
- Support real cases, not just fixtures: a small adapter turns a real `Case`'s
  already-computed verdict (`results`/`final_score`/`final_confidence`/
  `verdict_explanation.decisive_rule`) into the same dict shape
  `verdict_lock`/`prompt` already consume.
- Keep the verdict-lock as the safety net exactly as before: the generated
  narration is validated, never trusted blind.

## Non-goals

- **No automatic triggering on real cases.** The connector's manifest
  declares no events (`events=()`). Wiring to `EVENT_CASE_FINALISED` is a
  deliberately separate, future decision — see "Data governance" below for
  why.
- No report/email/UI rendering of generated narration. Output goes to the
  connector delivery ledger and stdout, for a human to read — same
  "human-in-the-loop" posture as the original spike.
- No training/fine-tuning — unchanged from the spike's own non-goals.
- No new secret-storage mechanism — API keys use the connector framework's
  existing `ConfigField(type="secret")` → Vault-overlay path, unchanged.

## Data governance (why this isn't wired to real events yet)

Once an external provider is configured, generating a narration for a real
case means sending that case's analyzer reports — and for mail cases,
content derived from a real phishing email — to a third-party API
(OpenAI/Anthropic/Google). The LLM Council that reviewed the original
training proposal flagged this as a genuine, unresolved CERT data-governance
question, separate from and more serious than API redistribution ToS. This
spec does not resolve that question. It keeps the blast radius to "a human
explicitly runs a command naming one case id or a fixture," not "every case
finalized while the connector happens to be enabled." Real-event wiring
should not happen until that governance question has an actual answer.

## Architecture

Three layers, each independently testable:

1. **Provider adapters** (`connectors/contrib/ai_narration/providers/`) — one
   module per provider (`ollama`, `openai`, `anthropic`, `gemini`), each
   exposing a single `generate(prompt: str, config: dict) -> str`. Plain
   `requests` calls, no SDK dependencies — matches the spike's own
   `narration_spike.py` style.
2. **Provider selection** (`connectors/contrib/ai_narration/select.py`) —
   pure function, given the connector's config dict, returns which provider
   to use.
3. **The connector** (`connectors/contrib/ai_narration/connector.py`) — a
   `Connector` subclass whose `health_check()` reports the selected
   provider's reachability/configuredness. No `on_case_finalised`/
   `on_case_created` override (not subscribed to any event).

A management command (`connectors/management/commands/test_ai_narration.py`)
is the only way to actually drive this end to end in this phase: it loads a
verdict+reports payload (from a fixture file or a real case id via the new
adapter), builds the prompt, asks the connector's own `select_provider` +
provider adapter for a narration, validates it, and records a
`ConnectorDelivery` row.

## Components

### `connectors/contrib/ai_narration/select.py`

```python
from typing import Callable

from .providers import anthropic, gemini, ollama, openai

_EXTERNAL_PRIORITY = ("openai", "anthropic", "gemini")

PROVIDERS: dict[str, Callable[[str, dict], str]] = {
    "ollama": ollama.generate,
    "openai": openai.generate,
    "anthropic": anthropic.generate,
    "gemini": gemini.generate,
}


def select_provider(config: dict) -> tuple[str, Callable[[str, dict], str]]:
    """Auto-detect which provider to use: the first external provider (in
    _EXTERNAL_PRIORITY order) with a non-empty API key wins; otherwise
    Ollama (assumed always a candidate — its own health_check call is what
    actually proves reachability, not this selection)."""
    for name in _EXTERNAL_PRIORITY:
        if config.get(f"{name}_api_key"):
            return name, PROVIDERS[name]
    return "ollama", PROVIDERS["ollama"]
```

### `connectors/contrib/ai_narration/providers/ollama.py`

```python
"""Local Ollama provider — plain HTTP, no SDK. Mirrors
score_process/management/commands/narration_spike.py's own Ollama call."""
import requests


def generate(prompt: str, config: dict) -> str:
    url = config.get("ollama_url", "http://localhost:11434")
    model = config.get("ollama_model", "qwen2.5:7b-instruct")
    response = requests.post(
        f"{url}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False},
        timeout=600,
    )
    response.raise_for_status()
    return response.json().get("response", "")
```

### `connectors/contrib/ai_narration/providers/openai.py`

```python
"""OpenAI provider — plain HTTP, no SDK."""
import requests


def generate(prompt: str, config: dict) -> str:
    api_key = config["openai_api_key"]
    model = config.get("openai_model", "gpt-4o-mini")
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"model": model, "messages": [{"role": "user", "content": prompt}]},
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]
```

### `connectors/contrib/ai_narration/providers/anthropic.py`

```python
"""Anthropic provider — plain HTTP, no SDK."""
import requests

_API_VERSION = "2023-06-01"


def generate(prompt: str, config: dict) -> str:
    api_key = config["anthropic_api_key"]
    model = config.get("anthropic_model", "claude-haiku-4-5-20251001")
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": _API_VERSION,
        },
        json={
            "model": model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["content"][0]["text"]
```

### `connectors/contrib/ai_narration/providers/gemini.py`

```python
"""Google Gemini provider — plain HTTP, no SDK."""
import requests


def generate(prompt: str, config: dict) -> str:
    api_key = config["gemini_api_key"]
    model = config.get("gemini_model", "gemini-2.5-flash")
    response = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        headers={"x-goog-api-key": api_key},
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["candidates"][0]["content"]["parts"][0]["text"]
```

### `connectors/contrib/ai_narration/adapters.py`

```python
"""Turns a real Case's already-computed verdict into the dict shape
score_process.scoring.narration.{verdict_lock,prompt} expect. Never re-
derives the verdict -- reads only fields the scoring engines already wrote."""
from case_handler.models import Case


def case_to_verdict_dict(case: Case) -> dict:
    rule = "unknown"
    if case.verdict_explanation:
        rule = case.verdict_explanation.get("decisive_rule", "unknown")
    return {
        "band": case.results,
        "score": case.final_score,
        "confidence": case.final_confidence,
        "rule": rule,
    }
```

### `connectors/contrib/ai_narration/connector.py`

```python
"""AI narration connector -- architecture test only, see design doc's
Non-goals. Not subscribed to any event; drive it via
`manage.py test_ai_narration`."""
from connectors.base import Connector, ConnectorManifest, ConfigField, HealthStatus

from .select import select_provider


class AiNarrationConnector(Connector):
    manifest = ConnectorManifest(
        name="ai_narration",
        version="0.1.0",
        author="Thales CERT",
        category="AI",
        description=(
            "Generates a plain-language case narration via a locally-run or "
            "externally-configured LLM, validated against the case's "
            "already-computed verdict. Manual/fixture-triggered only in "
            "this phase -- see docs/specs/2026-09-21-ai-narration-connector-design.md."
        ),
        config_schema=(
            ConfigField("ollama_url", type="url", default="http://localhost:11434"),
            ConfigField("ollama_model", type="str", default="qwen2.5:7b-instruct"),
            ConfigField("openai_api_key", type="secret"),
            ConfigField("openai_model", type="str", default="gpt-4o-mini"),
            ConfigField("anthropic_api_key", type="secret"),
            ConfigField("anthropic_model", type="str", default="claude-haiku-4-5-20251001"),
            ConfigField("gemini_api_key", type="secret"),
            ConfigField("gemini_model", type="str", default="gemini-2.5-flash"),
        ),
        events=(),
        enabled_by_default=False,
    )

    def health_check(self) -> HealthStatus:
        name, generate = select_provider(self.config)
        if name != "ollama":
            has_key = bool(self.config.get(f"{name}_api_key"))
            return HealthStatus(
                ok=has_key,
                detail=f"selected provider: {name} ({'configured' if has_key else 'no API key'})",
            )
        import requests
        url = self.config.get("ollama_url", "http://localhost:11434")
        try:
            requests.get(f"{url}/api/version", timeout=5).raise_for_status()
            return HealthStatus(ok=True, detail=f"selected provider: ollama ({url}, reachable)")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=f"selected provider: ollama ({url}) unreachable: {exc}")
```

### `connectors/management/commands/test_ai_narration.py`

CLI: `manage.py test_ai_narration [--case-id N | --fixture PATH]`

- Loads verdict + analyzer_reports: from the fixture JSON (same shape the
  narration-spike fixtures already use), or via `adapters.case_to_verdict_dict`
  plus the real case's `AnalyzerReport` rows for `--case-id`.
- `build_prompt(verdict, analyzer_reports)` (reused from
  `score_process.scoring.narration.prompt`, unchanged).
- `registry.instantiate("ai_narration")` to get a configured connector
  instance; `select_provider(connector.config)` then the chosen
  `generate(prompt, connector.config)`.
- `validate_narration(narration, verdict)` (reused from
  `score_process.scoring.narration.verdict_lock`, unchanged).
- Writes one `ConnectorDelivery` row: `connector="ai_narration"`,
  `event="manual_test"`, `case_id=<id or None>`,
  `status="success"|"failed"`, `error=<provider exception, if any>`.
- Prints the chosen provider, PASS/FAIL, and the narration text.

## Data Flow

```
--case-id N  -> adapters.case_to_verdict_dict(Case.objects.get(pk=N))
                + real AnalyzerReport rows for that case
--fixture F  -> fixture JSON (same shape as the spike's fixtures)
             -> build_prompt(verdict, analyzer_reports)
             -> select_provider(connector.config) -> (name, generate)
             -> generate(prompt, connector.config) -> raw narration text
             -> validate_narration(narration, verdict)
             -> ConnectorDelivery row + printed PASS/FAIL + narration
```

## Error Handling

- Connector disabled: `connectors.delivery.get_state("ai_narration").enabled`
  is `False` — including the very first run, since `get_state` lazily seeds
  a `ConnectorState` row from `manifest.enabled_by_default` (`False` here),
  so an unconfigured connector defaults closed. The command checks this and
  refuses to run, printing which admin action would enable it. No
  `ConnectorDelivery` row.
- No provider usable at all (no external key, Ollama unreachable): command
  exits non-zero before attempting generation. No `ConnectorDelivery` row —
  nothing was actually attempted.
- Provider call raises (timeout, HTTP error, malformed response): caught,
  recorded as `ConnectorDelivery(status="failed", error=str(exc))`, command
  exits non-zero.
- Validation failing is not an error: `ConnectorDelivery(status="success")`
  still (the provider call succeeded) — the FAIL and its reasons are part of
  the printed/recorded result, exactly like the original spike's philosophy.
- `--case-id` pointing at a case with no `verdict_explanation` yet (never
  finalized): fail fast with a clear message naming the missing field,
  before any provider call.

## Testing

- `select.py`: unit tests — no key configured → ollama; one external key
  configured → that provider; multiple external keys configured → priority
  order respected.
- Each provider adapter: unit test with a mocked `requests.post`/`get`
  response, asserting the request shape (URL, headers, payload) and that
  the response is parsed correctly. No live network calls in CI.
- `adapters.case_to_verdict_dict`: unit test against a real `Case` fixture
  with and without `verdict_explanation` set.
- `connector.py`'s `health_check`: unit tests for each of the three
  situations (external configured, external unconfigured, ollama reachable/
  unreachable) with `requests` mocked.
- `test_ai_narration` command: a smoke test with the connector disabled
  (asserts refusal, no `ConnectorDelivery` row) and one with it enabled and
  all providers mocked (asserts the `ConnectorDelivery` row's shape) — no
  live model call in CI, same posture as `narration_spike`'s own test.

## Open Questions / Follow-on Work (not in this spec)

- Real `on_case_finalised` wiring — contingent on the data-governance
  question above actually being answered, not on anything technical here.
- Report/email/UI rendering of a generated narration — contingent on the
  above, plus its own design pass (where does it render, does it replace or
  augment `verdict_explanation`, caching/regeneration policy).
- Per-provider circuit breaking — `connectors.registry.register` already
  calls `ensure_breaker(manifest.name)` for every connector; whether that
  breaker should be provider-scoped (separate trip state per provider, not
  per connector) is worth revisiting once this fires automatically.
- Cost/rate-limit handling for paid external providers is entirely
  unaddressed here — acceptable for a human-triggered-one-case-at-a-time
  test command, not acceptable once/if this becomes automatic.
