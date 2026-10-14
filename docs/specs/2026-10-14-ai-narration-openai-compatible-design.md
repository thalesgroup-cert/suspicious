# AI Narration: OpenAI-Compatible Endpoint: Design

> Amends `docs/specs/2026-09-21-ai-narration-event-wiring-design.md`: the
> automatic `case_finalised` path is no longer hardcoded to Ollama. It is
> restricted to an explicit two-provider allowlist (Ollama, or an
> operator-declared OpenAI-compatible endpoint). Everything else in that
> spec, and in `2026-09-21-ai-narration-connector-design.md`, still holds.

Resolves GitHub issue #406.

## Context

`ai_narration` supports four providers: local Ollama, OpenAI, Anthropic,
Gemini. The three vendor providers are hardcoded to their vendor endpoints.
There is no slot for an internal or self-hosted model served behind an
OpenAI-compatible Chat Completions API (vLLM, Triton, an internal gateway,
or a vendor-hosted compatible endpoint such as the GLM family).

Issue #406 proposes making the `openai` adapter's base URL configurable.
That alone does not meet the reporter's goal. The event-driven hook calls
`ollama.generate` directly and never consults `select_provider`, so a
configurable OpenAI base URL would only be reachable from the manual
`manage.py test_ai_narration` command. Automatic narration against an
internal endpoint would stay impossible.

The data-governance rule from the event-wiring spec was "real case content
never reaches an external provider automatically". Its own text names the
real trust boundary: `ollama_url` is an operator-configurable setting, so
"Ollama only" never meant "stays on this machine". An operator who points
the connector at an internal OpenAI-compatible URL makes the same
declaration. This spec extends the automatic path to that case, and only
that case.

## Goals

- Let an admin point `ai_narration` at any OpenAI-compatible
  `/chat/completions` endpoint and have it fire on `case_finalised`.
- Make that an explicit, deliberate opt-in. Default behaviour (Ollama) is
  unchanged for every existing deployment.
- Keep OpenAI, Anthropic and Gemini unreachable from the automatic path,
  enforced in code, not by convention.
- Report real reachability of the configured endpoint in `health_check`.

## Non-goals

- No change to the vendor providers (`openai.py`, `anthropic.py`,
  `gemini.py`). Issue #406's literal proposal (`openai_base_url` on the
  vendor adapter) is rejected: that adapter means "the real OpenAI", and
  giving it a configurable host would blur exactly the distinction the
  allowlist depends on.
- No change to `_EXTERNAL_PRIORITY`. The new provider is never chosen by
  API-key presence.
- No replacement of the native Ollama provider. Ollama also serves
  `/v1/chat/completions`, but the native call sets `options.num_ctx = 8192`
  and the compatibility endpoint cannot, which risks silent prompt
  truncation. Native stays.
- No SDK dependency, no LiteLLM-style model-prefix routing, no env-var
  configuration. Plain `requests`, DB-backed config, like the other
  providers.
- No new secret mechanism. `ConfigField(type="secret")` already flows
  through the Vault overlay.
- No report/email/UI rendering of narration. Still log-only.

## Convention followed

Surveyed from the official docs of the OpenAI SDK, LangChain `ChatOpenAI`,
Open WebUI + vLLM, Ollama's OpenAI compatibility page and the BigModel (GLM)
API reference:

- The configured **base URL includes the version prefix**; the client
  appends `/chat/completions`. OpenAI: `https://api.openai.com/v1`. Ollama:
  `http://localhost:11434/v1`. GLM: `https://open.bigmodel.cn/api/paas/v4`.
  Hardcoding `/v1/chat/completions`, as the issue proposes, would break
  GLM, the issue's own example.
- Config is a flat triple: base URL, API key, model.
- The API key is often unused by self-hosted servers (vLLM, Ollama), so it
  must be optional.

## Architecture

Additive. One new provider module, one new selector function, one new
dispatch step in the hook, three new config fields plus the selector field.

### Config (manifest `config_schema`)

```python
ConfigField("narration_provider", type="str", default="ollama",
            help="Provider used when narration fires automatically: "
                 "'ollama' or 'openai_compatible'."),
ConfigField("openai_compatible_base_url", type="url",
            help="Base URL including version prefix, e.g. https://gw.internal/v1. "
                 "No default: must be set deliberately."),
ConfigField("openai_compatible_api_key", type="secret",
            help="Optional. Omit for servers that do not check a key."),
ConfigField("openai_compatible_model", type="str", required=False),
```

`openai_compatible_base_url` has **no default**. Defaulting it to
`api.openai.com` would let a half-finished config send case content to
OpenAI automatically. An unset base URL with `narration_provider =
openai_compatible` is a configuration error, not a fallback.

### `providers/openai_compatible.py`

```python
def generate(prompt: str, config: dict) -> str:
    base = (config.get("openai_compatible_base_url") or "").strip().rstrip("/")
    if not base:
        raise ValueError("openai_compatible_base_url is not set")
    if not base.startswith(("http://", "https://")):
        raise ValueError("openai_compatible_base_url must be http(s)")
    model = config.get("openai_compatible_model") or ""
    if not model:
        raise ValueError("openai_compatible_model is not set")
    headers = {}
    if config.get("openai_compatible_api_key"):
        headers["Authorization"] = f"Bearer {config['openai_compatible_api_key']}"
    response = requests.post(
        f"{base}/chat/completions",
        headers=headers,
        json={"model": model, "messages": [{"role": "user", "content": prompt}]},
        timeout=120,
    )
    response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"]
    if not content:
        raise ValueError("openai_compatible endpoint returned empty content")
    return content
```

- No `Authorization` header when the key is blank.
- No default model: model names are endpoint-specific, and a wrong default
  would produce confusing 404s.
- Empty content raises. Reasoning models can return the answer in a
  separate field with `content` empty. A loud failure lands in the delivery
  ledger and retries, instead of validating an empty narration.
- TLS verification stays on. Internal CAs are handled via the standard
  `REQUESTS_CA_BUNDLE` environment variable, no new field.

### `select.py` (additive)

```python
AUTO_PROVIDERS = ("ollama", "openai_compatible")

PROVIDERS["openai_compatible"] = openai_compatible.generate   # _EXTERNAL_PRIORITY unchanged

def select_auto_provider(config) -> tuple[str, Callable[[str, dict], str]]:
    """Provider for the event-driven path. Allowlist only; never auto-detected."""
    name = (config.get("narration_provider") or "ollama").strip()
    if name not in AUTO_PROVIDERS:
        raise ValueError(
            f"narration_provider {name!r} is not allowed on the automatic path "
            f"(allowed: {', '.join(AUTO_PROVIDERS)})"
        )
    return name, PROVIDERS[name]
```

`select_provider` (manual command, `health_check`) gains one rule at the
top: if `narration_provider` is set to a name in `PROVIDERS`, return it.
Otherwise the existing key-presence detection runs unchanged. This lets the
manual command exercise `openai_compatible` and keeps one selector story.

An unknown or disallowed `narration_provider` on the automatic path raises
`ValueError`. The framework records a failed `ConnectorDelivery` and
retries, so a typo or an attempt to select `openai` is visible in the
ledger and never silently falls back to a different provider.

### `connector.py`

- Manifest `description` and module docstring: replace "(Ollama only)" with
  the two-provider allowlist.
- `on_case_finalised`: replace `ollama.generate(prompt, self.config)` with

  ```python
  provider_name, generate = select_auto_provider(self.config)
  narration = generate(prompt, self.config)
  ```

  and log `provider=%s` with `provider_name` instead of the literal
  `ollama`.
- `health_check` gains an `openai_compatible` branch (below). Other
  branches unchanged.

### `health_check` for `openai_compatible`

`GET {base}/models` (5 s timeout, `Authorization` header when a key is set):

| Result | Status |
|---|---|
| 2xx | ok, "reachable" |
| 404 | ok, "reachable (no /models route)", gateways often omit it |
| 401 / 403 | not ok, "authentication failed" |
| other 4xx, 5xx, timeout, connection error | not ok, with detail |
| base URL unset | not ok, "openai_compatible_base_url not set" |

`health_check` must not raise; every branch returns a `HealthStatus`.

## Example configuration (GLM)

```
narration_provider          = openai_compatible
openai_compatible_base_url  = https://open.bigmodel.cn/api/paas/v4
openai_compatible_api_key   = <secret>
openai_compatible_model     = glm-5.3-flash
```

## Data governance

- Default is unchanged: nothing leaves the Ollama host an operator already
  configured.
- Switching to `openai_compatible` is an explicit admin act on two fields
  (`narration_provider` and a base URL with no default). It cannot happen
  by key presence, by upgrade, or by a partial config.
- The base URL is admin-only configuration, the same trust level as
  `ollama_url`. The operator is declaring that endpoint trusted. A vendor
  endpoint set here is a deliberate decision to send case content to that
  vendor. Docs must say so plainly.
- OpenAI, Anthropic and Gemini remain manual-only, enforced by
  `AUTO_PROVIDERS`.
- Prompt-injection and log-retention notes from the event-wiring spec apply
  unchanged.

## Testing

- `openai_compatible.generate` (in `test_contrib_ai_narration_providers.py`):
  - posts to `{base}/chat/completions`; a trailing slash on the base URL
    does not double up; a non-`/v1` prefix (`/api/paas/v4`) is preserved
  - `Authorization` header present with a key, absent without
  - raises on missing/non-http base URL, missing model, empty content
- `select_auto_provider` (in `test_contrib_ai_narration_select.py`):
  - unset / blank / `ollama` → ollama
  - `openai_compatible` → openai_compatible
  - `openai`, `anthropic`, `gemini`, unknown → `ValueError`
  - presence of `openai_api_key` etc. never changes the result
- `select_provider`: explicit `narration_provider = openai_compatible` wins;
  unset behaves exactly as before (existing tests untouched).
- `on_case_finalised` (in `test_contrib_ai_narration.py`): with
  `narration_provider = openai_compatible`, the openai_compatible generate
  mock is called, ollama's is not, and the log line carries
  `provider=openai_compatible`. With a disallowed value, the hook raises and
  no provider is called. Existing Ollama-default tests stay green.
- `health_check`: one test per row of the table above, using mocked
  `requests.get`.
- Manifest test: new fields present, `openai_compatible_api_key` is
  `secret`, `openai_compatible_base_url` has no default.

## Documentation to update with the change

- `Suspicious/Suspicious/connectors/README.md`: rewrite the "Ollama-only
  restriction" section as the two-provider allowlist.
- `docs/operations/integrations.md` row for `ai_narration`.
- Back-reference note at the top of the event-wiring spec (added with this
  spec).

## Open Questions / Follow-on Work (not in this spec)

- `health_check` still derives its provider from `select_provider`
  (key-presence unless `narration_provider` is set), while the automatic
  path uses `select_auto_provider`. With `narration_provider` unset and a
  vendor key present, health reports the vendor while events use Ollama.
  Pre-existing; aligning them changes what the manual command gates on, so
  it is left for a separate change.
- A per-endpoint TLS-verify or CA-path field, if `REQUESTS_CA_BUNDLE` proves
  awkward for operators.
- A `/chat/completions` response-format option for reasoning models whose
  answer is not in `content`.
