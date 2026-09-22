# AI Narration Connector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the verdict-narration spike into an activatable, provider-configurable connector (local Ollama or a configured external provider), reusing the existing `connectors` app for activation/config/secrets/audit-trail, driven manually by a management command — no automatic event wiring yet.

**Architecture:** Three pure/independent layers (provider adapters, provider selection, a real-case-to-verdict-dict adapter) plus a thin `Connector` subclass and a management command that wires them together against either a real case or a fixture.

**Tech Stack:** Python, Django management commands, the existing `connectors` app framework, `requests` (already a dependency).

**Spec:** `docs/specs/2026-09-21-ai-narration-connector-design.md`

## Global Constraints

- No new Python dependencies — `requests` and stdlib only.
- Provider adapter modules (`providers/*.py`) and `select.py` must not import Django models — pure functions of `(prompt, config) -> str` / `(config) -> (name, callable)`.
- The connector's manifest MUST have `events=()` (no event subscription) and `enabled_by_default=False` — this phase is manual/fixture-triggered only, per the spec's Non-goals. Do not add an `on_case_finalised` override.
- No report/email/UI changes anywhere in this plan.
- Never include an API key or request header in a `ConnectorDelivery.error` value or in command output — only `str(exc)` from a `requests` exception (which does not include request headers by default).
- This repo is public — no commit may carry Claude/session attribution trailers or "Generated with Claude Code" text.
- Test files for provider adapters and `select.py` use `SimpleTestCase` with `requests` mocked — no live network calls in CI. Tests touching `Case`/`AnalyzerReport`/`ConnectorDelivery` use `TestCase` (real DB).

---

### Task 1: Provider adapters

**Files:**
- Create: `Suspicious/Suspicious/connectors/contrib/ai_narration/__init__.py` (empty)
- Create: `Suspicious/Suspicious/connectors/contrib/ai_narration/providers/__init__.py` (empty)
- Create: `Suspicious/Suspicious/connectors/contrib/ai_narration/providers/ollama.py`
- Create: `Suspicious/Suspicious/connectors/contrib/ai_narration/providers/openai.py`
- Create: `Suspicious/Suspicious/connectors/contrib/ai_narration/providers/anthropic.py`
- Create: `Suspicious/Suspicious/connectors/contrib/ai_narration/providers/gemini.py`
- Test: `Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_providers.py`

**Interfaces:**
- Produces: each module exposes `generate(prompt: str, config: dict) -> str`, raising on any HTTP/parse failure (never swallows an error — the caller records it).

- [ ] **Step 1: Write the failing tests**

```python
# Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_providers.py
from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.ai_narration.providers import anthropic, gemini, ollama, openai


class OllamaProviderTest(SimpleTestCase):
    @mock.patch("connectors.contrib.ai_narration.providers.ollama.requests.post")
    def test_generate_posts_expected_shape_and_parses_response(self, mock_post):
        mock_post.return_value = mock.Mock(
            json=lambda: {"response": "hello from ollama"},
        )
        mock_post.return_value.raise_for_status = lambda: None
        text = ollama.generate("a prompt", {"ollama_url": "http://x:11434", "ollama_model": "qwen2.5:7b-instruct"})
        self.assertEqual(text, "hello from ollama")
        url, kwargs = mock_post.call_args
        self.assertEqual(url[0], "http://x:11434/api/generate")
        self.assertEqual(kwargs["json"]["model"], "qwen2.5:7b-instruct")
        self.assertEqual(kwargs["json"]["prompt"], "a prompt")

    @mock.patch("connectors.contrib.ai_narration.providers.ollama.requests.post")
    def test_generate_uses_defaults_when_config_empty(self, mock_post):
        mock_post.return_value = mock.Mock(json=lambda: {"response": "x"})
        mock_post.return_value.raise_for_status = lambda: None
        ollama.generate("p", {})
        url, kwargs = mock_post.call_args
        self.assertEqual(url[0], "http://localhost:11434/api/generate")
        self.assertEqual(kwargs["json"]["model"], "qwen2.5:7b-instruct")


class OpenAIProviderTest(SimpleTestCase):
    @mock.patch("connectors.contrib.ai_narration.providers.openai.requests.post")
    def test_generate_posts_expected_shape_and_parses_response(self, mock_post):
        mock_post.return_value = mock.Mock(
            json=lambda: {"choices": [{"message": {"content": "hello from openai"}}]},
        )
        mock_post.return_value.raise_for_status = lambda: None
        text = openai.generate("a prompt", {"openai_api_key": "sk-test", "openai_model": "gpt-4o-mini"})
        self.assertEqual(text, "hello from openai")
        url, kwargs = mock_post.call_args
        self.assertEqual(url[0], "https://api.openai.com/v1/chat/completions")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer sk-test")
        self.assertEqual(kwargs["json"]["messages"][0]["content"], "a prompt")


class AnthropicProviderTest(SimpleTestCase):
    @mock.patch("connectors.contrib.ai_narration.providers.anthropic.requests.post")
    def test_generate_posts_expected_shape_and_parses_response(self, mock_post):
        mock_post.return_value = mock.Mock(
            json=lambda: {"content": [{"text": "hello from anthropic"}]},
        )
        mock_post.return_value.raise_for_status = lambda: None
        text = anthropic.generate("a prompt", {"anthropic_api_key": "ak-test"})
        self.assertEqual(text, "hello from anthropic")
        url, kwargs = mock_post.call_args
        self.assertEqual(url[0], "https://api.anthropic.com/v1/messages")
        self.assertEqual(kwargs["headers"]["x-api-key"], "ak-test")
        self.assertEqual(kwargs["json"]["messages"][0]["content"], "a prompt")


class GeminiProviderTest(SimpleTestCase):
    @mock.patch("connectors.contrib.ai_narration.providers.gemini.requests.post")
    def test_generate_posts_expected_shape_and_parses_response(self, mock_post):
        mock_post.return_value = mock.Mock(
            json=lambda: {"candidates": [{"content": {"parts": [{"text": "hello from gemini"}]}}]},
        )
        mock_post.return_value.raise_for_status = lambda: None
        text = gemini.generate("a prompt", {"gemini_api_key": "gk-test", "gemini_model": "gemini-2.5-flash"})
        self.assertEqual(text, "hello from gemini")
        url, kwargs = mock_post.call_args
        self.assertIn("gemini-2.5-flash", url[0])
        self.assertEqual(kwargs["headers"]["x-goog-api-key"], "gk-test")
        self.assertEqual(kwargs["json"]["contents"][0]["parts"][0]["text"], "a prompt")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python manage.py test connectors.tests.test_contrib_ai_narration_providers -v 2`
Expected: FAIL — `connectors.contrib.ai_narration` module does not exist yet.

- [ ] **Step 3: Write the implementation**

```python
# Suspicious/Suspicious/connectors/contrib/ai_narration/__init__.py
```
(empty file)

```python
# Suspicious/Suspicious/connectors/contrib/ai_narration/providers/__init__.py
```
(empty file)

```python
# Suspicious/Suspicious/connectors/contrib/ai_narration/providers/ollama.py
"""Local Ollama provider -- plain HTTP, no SDK. Mirrors
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

```python
# Suspicious/Suspicious/connectors/contrib/ai_narration/providers/openai.py
"""OpenAI provider -- plain HTTP, no SDK."""
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

```python
# Suspicious/Suspicious/connectors/contrib/ai_narration/providers/anthropic.py
"""Anthropic provider -- plain HTTP, no SDK."""
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

```python
# Suspicious/Suspicious/connectors/contrib/ai_narration/providers/gemini.py
"""Google Gemini provider -- plain HTTP, no SDK."""
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `python manage.py test connectors.tests.test_contrib_ai_narration_providers -v 2`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/connectors/contrib/ai_narration/ Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_providers.py
git commit -m "feat(connectors): add ai_narration provider adapters (ollama/openai/anthropic/gemini)"
```

---

### Task 2: Provider selection

**Files:**
- Create: `Suspicious/Suspicious/connectors/contrib/ai_narration/select.py`
- Test: `Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_select.py`

**Interfaces:**
- Consumes: the four `generate(prompt, config) -> str` callables from Task 1 (`connectors.contrib.ai_narration.providers.{ollama,openai,anthropic,gemini}`).
- Produces: `PROVIDERS: dict[str, Callable]`, `select_provider(config: dict) -> tuple[str, Callable]`.

- [ ] **Step 1: Write the failing tests**

```python
# Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_select.py
from django.test import SimpleTestCase

from connectors.contrib.ai_narration.select import select_provider
from connectors.contrib.ai_narration.providers import anthropic, gemini, ollama, openai


class SelectProviderTest(SimpleTestCase):
    def test_no_keys_configured_falls_back_to_ollama(self):
        name, fn = select_provider({})
        self.assertEqual(name, "ollama")
        self.assertIs(fn, ollama.generate)

    def test_openai_key_selects_openai(self):
        name, fn = select_provider({"openai_api_key": "sk-x"})
        self.assertEqual(name, "openai")
        self.assertIs(fn, openai.generate)

    def test_anthropic_key_selects_anthropic(self):
        name, fn = select_provider({"anthropic_api_key": "ak-x"})
        self.assertEqual(name, "anthropic")
        self.assertIs(fn, anthropic.generate)

    def test_gemini_key_selects_gemini(self):
        name, fn = select_provider({"gemini_api_key": "gk-x"})
        self.assertEqual(name, "gemini")
        self.assertIs(fn, gemini.generate)

    def test_priority_order_openai_before_anthropic_before_gemini(self):
        name, _ = select_provider({
            "openai_api_key": "sk-x", "anthropic_api_key": "ak-x", "gemini_api_key": "gk-x",
        })
        self.assertEqual(name, "openai")
        name, _ = select_provider({"anthropic_api_key": "ak-x", "gemini_api_key": "gk-x"})
        self.assertEqual(name, "anthropic")

    def test_empty_string_key_does_not_count_as_configured(self):
        name, _ = select_provider({"openai_api_key": ""})
        self.assertEqual(name, "ollama")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python manage.py test connectors.tests.test_contrib_ai_narration_select -v 2`
Expected: FAIL — `connectors.contrib.ai_narration.select` does not exist yet.

- [ ] **Step 3: Write the implementation**

```python
# Suspicious/Suspicious/connectors/contrib/ai_narration/select.py
"""Auto-detect which provider a case narration should use. Pure -- no ORM,
no Django models."""
from __future__ import annotations

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
    """The first external provider (in _EXTERNAL_PRIORITY order) with a
    non-empty API key wins; otherwise Ollama. Ollama's own reachability is
    proven by health_check, not by this selection."""
    for name in _EXTERNAL_PRIORITY:
        if config.get(f"{name}_api_key"):
            return name, PROVIDERS[name]
    return "ollama", PROVIDERS["ollama"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python manage.py test connectors.tests.test_contrib_ai_narration_select -v 2`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/connectors/contrib/ai_narration/select.py Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_select.py
git commit -m "feat(connectors): add ai_narration provider auto-selection"
```

---

### Task 3: Real-case verdict adapter

**Files:**
- Create: `Suspicious/Suspicious/connectors/contrib/ai_narration/adapters.py`
- Test: `Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_adapters.py`

**Interfaces:**
- Produces: `case_to_verdict_dict(case: Case) -> dict` with keys `band`, `score`, `confidence`, `rule` — the same shape `score_process.scoring.narration.prompt.build_prompt` and `verdict_lock.validate_narration` already consume.

- [ ] **Step 1: Write the failing tests**

```python
# Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_adapters.py
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, ObservableGroup
from connectors.contrib.ai_narration.adapters import case_to_verdict_dict


class CaseToVerdictDictTest(TestCase):
    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r", password="x")
        group = ObservableGroup.objects.create(label="g")
        self.case = Case.objects.create(
            observable_group=group, reporter=reporter, description="",
            results="Dangerous", final_score=9.2, final_confidence=88,
        )

    def test_uses_decisive_rule_from_verdict_explanation(self):
        self.case.verdict_explanation = {"band": "Dangerous", "confidence": 88, "decisive_rule": "embedded-ioc-escalation"}
        self.case.save(update_fields=["verdict_explanation"])
        result = case_to_verdict_dict(self.case)
        self.assertEqual(result, {
            "band": "Dangerous", "score": 9.2, "confidence": 88, "rule": "embedded-ioc-escalation",
        })

    def test_rule_is_unknown_when_no_verdict_explanation(self):
        result = case_to_verdict_dict(self.case)
        self.assertEqual(result["rule"], "unknown")
        self.assertEqual(result["band"], "Dangerous")
        self.assertEqual(result["score"], 9.2)
        self.assertEqual(result["confidence"], 88)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python manage.py test connectors.tests.test_contrib_ai_narration_adapters -v 2`
Expected: FAIL — `connectors.contrib.ai_narration.adapters` does not exist yet.

- [ ] **Step 3: Write the implementation**

```python
# Suspicious/Suspicious/connectors/contrib/ai_narration/adapters.py
"""Turns a real Case's already-computed verdict into the dict shape
score_process.scoring.narration.{verdict_lock,prompt} expect. Never
re-derives the verdict -- reads only fields the scoring engines already
wrote."""
from __future__ import annotations

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

- [ ] **Step 4: Run test to verify it passes**

Run: `python manage.py test connectors.tests.test_contrib_ai_narration_adapters -v 2`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/connectors/contrib/ai_narration/adapters.py Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_adapters.py
git commit -m "feat(connectors): add real-case-to-verdict-dict adapter for ai_narration"
```

---

### Task 4: The connector + registration

**Files:**
- Create: `Suspicious/Suspicious/connectors/contrib/ai_narration/connector.py`
- Modify: `Suspicious/Suspicious/connectors/contrib/__init__.py`
- Test: `Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration.py`

**Interfaces:**
- Consumes: `select_provider(config)` from Task 2 (`connectors.contrib.ai_narration.select`).
- Produces: `AiNarrationConnector(Connector)`, discoverable via `connectors.registry.registry` once registered in `BUILTIN_CONNECTOR_PATHS`.

- [ ] **Step 1: Write the failing tests**

```python
# Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration.py
from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.ai_narration.connector import AiNarrationConnector
from connectors.registry import registry


class AiNarrationManifestTest(SimpleTestCase):
    def test_manifest_valid_and_not_enabled_by_default(self):
        m = AiNarrationConnector.manifest
        m.validate()
        self.assertFalse(m.enabled_by_default)
        self.assertEqual(m.events, ())

    def test_registered_as_a_builtin(self):
        registry.discover()
        self.assertIn("ai_narration", registry.names())


class AiNarrationHealthCheckTest(SimpleTestCase):
    def test_external_provider_configured_reports_ok(self):
        connector = AiNarrationConnector({"openai_api_key": "sk-x"})
        status = connector.health_check()
        self.assertTrue(status.ok)
        self.assertIn("openai", status.detail)

    @mock.patch("connectors.contrib.ai_narration.connector.requests.get")
    def test_ollama_fallback_reachable_reports_ok(self, mock_get):
        mock_get.return_value = mock.Mock()
        mock_get.return_value.raise_for_status = lambda: None
        connector = AiNarrationConnector({})
        status = connector.health_check()
        self.assertTrue(status.ok)
        self.assertIn("ollama", status.detail)

    @mock.patch("connectors.contrib.ai_narration.connector.requests.get")
    def test_ollama_fallback_unreachable_reports_not_ok(self, mock_get):
        mock_get.side_effect = ConnectionError("refused")
        connector = AiNarrationConnector({})
        status = connector.health_check()
        self.assertFalse(status.ok)
        self.assertIn("ollama", status.detail)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python manage.py test connectors.tests.test_contrib_ai_narration -v 2`
Expected: FAIL — `connectors.contrib.ai_narration.connector` does not exist yet.

- [ ] **Step 3: Write the implementation**

```python
# Suspicious/Suspicious/connectors/contrib/ai_narration/connector.py
"""AI narration connector -- architecture test only, see
docs/specs/2026-09-21-ai-narration-connector-design.md's Non-goals. Not
subscribed to any event; drive it via `manage.py test_ai_narration`."""
from __future__ import annotations

import requests

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
            "this phase -- see "
            "docs/specs/2026-09-21-ai-narration-connector-design.md."
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
        name, _generate = select_provider(self.config)
        if name != "ollama":
            has_key = bool(self.config.get(f"{name}_api_key"))
            return HealthStatus(
                ok=has_key,
                detail=f"selected provider: {name} ({'configured' if has_key else 'no API key'})",
            )
        url = self.config.get("ollama_url", "http://localhost:11434")
        try:
            requests.get(f"{url}/api/version", timeout=5).raise_for_status()
            return HealthStatus(ok=True, detail=f"selected provider: ollama ({url}, reachable)")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(
                ok=False, detail=f"selected provider: ollama ({url}) unreachable: {exc}"
            )
```

- [ ] **Step 4: Register it as a builtin**

Modify `Suspicious/Suspicious/connectors/contrib/__init__.py` — add one line to the `BUILTIN_CONNECTOR_PATHS` tuple:

```python
BUILTIN_CONNECTOR_PATHS: tuple[str, ...] = (
    "connectors.contrib.misp.connector:MISPConnector",
    "connectors.contrib.thehive.connector:TheHiveConnector",
    "connectors.contrib.watcher.connector:WatcherConnector",
    "connectors.contrib.smtp_notify.connector:SmtpNotifyConnector",
    "connectors.contrib.chromadb.connector:ChromaDBConnector",
    "connectors.contrib.ai_narration.connector:AiNarrationConnector",
)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python manage.py test connectors.tests.test_contrib_ai_narration -v 2`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add Suspicious/Suspicious/connectors/contrib/ai_narration/connector.py Suspicious/Suspicious/connectors/contrib/__init__.py Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration.py
git commit -m "feat(connectors): add ai_narration connector, register as builtin"
```

---

### Task 5: The `test_ai_narration` management command

**Files:**
- Create: `Suspicious/Suspicious/connectors/management/__init__.py` (empty — this app has no management commands yet, the directory doesn't exist)
- Create: `Suspicious/Suspicious/connectors/management/commands/__init__.py` (empty)
- Create: `Suspicious/Suspicious/connectors/management/commands/test_ai_narration.py`
- Test: `Suspicious/Suspicious/connectors/tests/test_command_ai_narration.py`

**Interfaces:**
- Consumes: `connectors.delivery.get_state` (existing), `connectors.registry.registry.instantiate` (existing), `connectors.contrib.ai_narration.adapters.case_to_verdict_dict` (Task 3), `connectors.contrib.ai_narration.select.select_provider` (Task 2), `score_process.scoring.narration.prompt.build_prompt` (existing, from the narration spike), `score_process.scoring.narration.verdict_lock.validate_narration` (existing, from the narration spike), `api.utils.analyzer_reports.reports_for_case` (existing).
- Produces: a Django management command `manage.py test_ai_narration [--case-id N | --fixture PATH]`, writing one `ConnectorDelivery` row per successful or failed attempt.

- [ ] **Step 1: Write the failing tests**

```python
# Suspicious/Suspicious/connectors/tests/test_command_ai_narration.py
import json
import tempfile
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from case_handler.models import Case, ObservableGroup
from connectors.models import ConnectorDelivery, ConnectorState


class TestAiNarrationCommandTest(TestCase):
    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r", password="x")
        group = ObservableGroup.objects.create(label="g")
        self.case = Case.objects.create(
            observable_group=group, reporter=reporter, description="",
            results="Dangerous", final_score=9.2, final_confidence=88,
            verdict_explanation={"band": "Dangerous", "confidence": 88, "decisive_rule": "embedded-ioc-escalation"},
        )

    def _write_fixture(self):
        fixture = {
            "verdict": {"band": "Dangerous", "score": 9.2, "confidence": 88, "rule": "embedded-ioc-escalation"},
            "analyzer_reports": [{"analyzer": "VirusTotal_v3", "report_full": {"positives": 50, "total": 70}}],
        }
        tmp_dir = tempfile.mkdtemp()
        path = Path(tmp_dir) / "fixture.json"
        path.write_text(json.dumps(fixture))
        return path

    def test_refuses_when_connector_disabled(self):
        fixture_path = self._write_fixture()
        with self.assertRaises(CommandError):
            call_command("test_ai_narration", fixture=str(fixture_path))
        self.assertEqual(ConnectorDelivery.objects.count(), 0)

    def test_fixture_mode_records_success_delivery(self):
        ConnectorState.objects.update_or_create(name="ai_narration", defaults={"enabled": True})
        fixture_path = self._write_fixture()
        with mock.patch(
            "connectors.contrib.ai_narration.select.select_provider",
            return_value=("ollama", mock.Mock(return_value="This is Dangerous based on the evidence.")),
        ):
            call_command("test_ai_narration", fixture=str(fixture_path))
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual(delivery.connector, "ai_narration")
        self.assertEqual(delivery.event, "manual_test")
        self.assertIsNone(delivery.case_id)
        self.assertEqual(delivery.status, ConnectorDelivery.STATUS_SUCCESS)

    def test_case_id_mode_records_success_delivery_with_case_id(self):
        ConnectorState.objects.update_or_create(name="ai_narration", defaults={"enabled": True})
        with mock.patch(
            "connectors.contrib.ai_narration.select.select_provider",
            return_value=("ollama", mock.Mock(return_value="This is Dangerous based on the evidence.")),
        ):
            call_command("test_ai_narration", case_id=self.case.pk)
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual(delivery.case_id, self.case.pk)
        self.assertEqual(delivery.status, ConnectorDelivery.STATUS_SUCCESS)

    def test_case_without_verdict_explanation_fails_fast(self):
        ConnectorState.objects.update_or_create(name="ai_narration", defaults={"enabled": True})
        unfinalised = Case.objects.create(
            observable_group=self.case.observable_group, reporter=self.case.reporter, description="",
        )
        with self.assertRaises(CommandError):
            call_command("test_ai_narration", case_id=unfinalised.pk)
        self.assertEqual(ConnectorDelivery.objects.count(), 0)

    def test_provider_failure_records_failed_delivery(self):
        ConnectorState.objects.update_or_create(name="ai_narration", defaults={"enabled": True})
        fixture_path = self._write_fixture()

        def _boom(prompt, config):
            raise RuntimeError("provider unreachable")

        with mock.patch(
            "connectors.contrib.ai_narration.select.select_provider",
            return_value=("ollama", _boom),
        ):
            with self.assertRaises(CommandError):
                call_command("test_ai_narration", fixture=str(fixture_path))
        delivery = ConnectorDelivery.objects.get()
        self.assertEqual(delivery.status, ConnectorDelivery.STATUS_FAILED)
        self.assertIn("provider unreachable", delivery.error)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python manage.py test connectors.tests.test_command_ai_narration -v 2`
Expected: FAIL — the `test_ai_narration` command does not exist yet.

- [ ] **Step 3: Write the implementation**

```python
# Suspicious/Suspicious/connectors/management/commands/test_ai_narration.py
"""Manually drive the ai_narration connector against a real case or a
fixture. See docs/specs/2026-09-21-ai-narration-connector-design.md --
this command is the ONLY way to exercise the connector in this phase; it
is not wired to any automatic event."""
import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from api.utils.analyzer_reports import reports_for_case
from case_handler.models import Case
from connectors.contrib.ai_narration.adapters import case_to_verdict_dict
from connectors.contrib.ai_narration import select as select_module
from connectors.delivery import get_state
from connectors.models import ConnectorDelivery
from connectors.registry import registry
from score_process.scoring.narration.prompt import build_prompt
from score_process.scoring.narration.verdict_lock import validate_narration


class Command(BaseCommand):
    help = "Manually drive the ai_narration connector against a real case or a fixture."

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--case-id", type=int)
        group.add_argument("--fixture", type=str)

    def handle(self, *args, **options):
        if not get_state("ai_narration").enabled:
            raise CommandError(
                "ai_narration connector is disabled -- set "
                "ConnectorState.enabled=True for name='ai_narration' before running this command."
            )

        if options["case_id"] is not None:
            case_id = options["case_id"]
            try:
                case = Case.objects.get(pk=case_id)
            except Case.DoesNotExist:
                raise CommandError(f"no case with id {case_id}")
            if not case.verdict_explanation:
                raise CommandError(
                    f"case {case_id} has no verdict_explanation yet -- it hasn't been finalized"
                )
            verdict = case_to_verdict_dict(case)
            analyzer_reports = [
                {"analyzer": r.analyzer.name, "report_full": r.report_full}
                for r in reports_for_case(case)
            ]
        else:
            fixture_path = Path(options["fixture"])
            try:
                fixture = json.loads(fixture_path.read_text())
                verdict = fixture["verdict"]
                analyzer_reports = fixture["analyzer_reports"]
            except (OSError, json.JSONDecodeError, KeyError) as exc:
                raise CommandError(f"invalid fixture {fixture_path}: {exc}")
            case_id = None

        connector = registry.instantiate("ai_narration")
        prompt = build_prompt(verdict, analyzer_reports)
        provider_name, generate = select_module.select_provider(connector.config)

        started = timezone.now()
        try:
            narration = generate(prompt, connector.config)
        except Exception as exc:  # noqa: BLE001 — record it, don't crash unrecorded
            ConnectorDelivery.objects.create(
                connector="ai_narration", event="manual_test", case_id=case_id,
                status=ConnectorDelivery.STATUS_FAILED, error=str(exc),
                duration_ms=int((timezone.now() - started).total_seconds() * 1000),
            )
            raise CommandError(f"provider {provider_name} call failed: {exc}")

        result = validate_narration(narration, verdict)
        ConnectorDelivery.objects.create(
            connector="ai_narration", event="manual_test", case_id=case_id,
            status=ConnectorDelivery.STATUS_SUCCESS,
            duration_ms=int((timezone.now() - started).total_seconds() * 1000),
        )

        status = "PASS" if result.passed else "FAIL"
        self.stdout.write(f"provider: {provider_name}")
        self.stdout.write(f"STATUS: {status}")
        if result.reasons:
            self.stdout.write("REASONS:")
            for reason in result.reasons:
                self.stdout.write(f"  - {reason}")
        self.stdout.write("")
        self.stdout.write("NARRATION:")
        self.stdout.write(narration)
```

Note: the command imports `select as select_module` and calls
`select_module.select_provider(...)` (rather than `from .select import
select_provider`) specifically so the test file's
`mock.patch("connectors.contrib.ai_narration.select.select_provider", ...)`
actually takes effect — patching the name in the module where it's looked
up, not a copy already bound in the command's own namespace.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python manage.py test connectors.tests.test_command_ai_narration -v 2`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/connectors/management/ Suspicious/Suspicious/connectors/tests/test_command_ai_narration.py
git commit -m "feat(connectors): add test_ai_narration management command"
```
