# AI Narration Event Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Subscribe the existing `ai_narration` connector to `EVENT_CASE_FINALISED` so it narrates every finalised case automatically, hardcoded to local Ollama only — no path to an external provider from this trigger, ever.

**Architecture:** One shared helper extracted from the existing manual command into `adapters.py` (so both call sites use one implementation), one new method (`on_case_finalised`) on the existing `Connector` subclass, one manifest field change. No new modules, no framework changes — `connectors/delivery.py`'s existing circuit-breaker/retry/ledger machinery wraps the new hook exactly as it wraps every other connector's.

**Tech Stack:** Python, Django, the existing `connectors` app framework.

**Spec:** `docs/specs/2026-09-21-ai-narration-event-wiring-design.md`

## Global Constraints

- The event-driven path (`on_case_finalised`) must call `providers.ollama.generate` directly — never import or call `select_provider`. There must be no code path from an automatic event to an external provider.
- No report/email/UI rendering — narration stays log-only (`logger.info`) on this path, exactly as the spec's Non-goals state.
- `select.py`'s auto-detection logic is untouched — the manual `test_ai_narration` command keeps using it exactly as before.
- No new Python dependencies.
- This repo is public — no commit may carry Claude/session attribution trailers or "Generated with Claude Code" text.
- Tests for the new hook use `TestCase` (real DB, since the hook does `Case.objects.get`) with `providers.ollama.generate` mocked — no live network or Ollama process in CI.
- **Correction to the spec's Testing section**: it says to "move the existing dedup/cap tests from `test_command_ai_narration.py`... added in the prior fix wave" into the new adapters test file. Those tests do not exist — `test_command_ai_narration.py` has no test that exercises `_cap_report_full`'s truncation behavior or the dedup/cap-at-20 slicing directly (verified by grep before writing this plan). Task 1 below writes new tests for the extracted function instead of moving nonexistent ones; this is the correct read of "same coverage" — the behavior itself is unchanged, so this closes a real pre-existing gap rather than adding scope.

---

### Task 1: Extract `analyzer_reports_for_prompt` into `adapters.py`

**Files:**
- Modify: `Suspicious/Suspicious/connectors/contrib/ai_narration/adapters.py`
- Modify: `Suspicious/Suspicious/connectors/management/commands/test_ai_narration.py`
- Modify: `Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_adapters.py`

**Interfaces:**
- Consumes: `api.views.investigations._dedup_analyzer_reports(reports) -> list`, `api.utils.analyzer_reports.reports_for_case(case) -> QuerySet`, both existing and unchanged.
- Produces: `analyzer_reports_for_prompt(case: Case) -> list[dict]` — each dict shaped `{"analyzer": str, "report_full": dict}`, deduped, capped at 20 reports, each `report_full` capped at 4000 JSON-serialized chars. Task 2's `on_case_finalised` calls this.

- [ ] **Step 1: Write the failing tests**

Append to `Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_adapters.py` (it already imports `TestCase`, `Case`, `ObservableGroup` — add these imports at the top of the file alongside the existing ones, then add the new test class at the bottom):

```python
import json

from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP

from connectors.contrib.ai_narration.adapters import analyzer_reports_for_prompt


class AnalyzerReportsForPromptTest(TestCase):
    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r2", password="x")
        self.group = ObservableGroup.objects.create(label="g2")
        self.case = Case.objects.create(
            observable_group=self.group, reporter=reporter, description="",
            results="Dangerous", final_score=9.2, final_confidence=88,
        )
        self.ip = IP.objects.create(address="8.8.8.8")
        from case_handler.models import ObservableGroupArtifact
        ObservableGroupArtifact.objects.create(
            group=self.group, artifact_type="IP", ip=self.ip
        )
        self.analyzer = Analyzer.objects.create(
            name="GTI_Lookup", analyzer_cortex_id="gti1", tier=1
        )

    def test_caps_at_twenty_reports(self):
        for i in range(25):
            AnalyzerReport.objects.create(
                cortex_job_id=f"j{i}", type="ip", status="Success", analyzer=self.analyzer,
                ip=self.ip, level="malicious", confidence=90, score=10,
                report_summary={}, report_taxonomy={}, report_full={"n": i},
            )
        result = analyzer_reports_for_prompt(self.case)
        self.assertEqual(len(result), 20)

    def test_truncates_report_full_over_char_cap(self):
        big = {"payload": "x" * 5000}
        AnalyzerReport.objects.create(
            cortex_job_id="j-big", type="ip", status="Success", analyzer=self.analyzer,
            ip=self.ip, level="malicious", confidence=90, score=10,
            report_summary={}, report_taxonomy={}, report_full=big,
        )
        result = analyzer_reports_for_prompt(self.case)
        self.assertEqual(len(result), 1)
        report_full = result[0]["report_full"]
        self.assertTrue(report_full["_truncated"])
        self.assertEqual(report_full["original_size_chars"], len(json.dumps(big)))
        self.assertLessEqual(len(report_full["preview"]), 4000)

    def test_small_report_full_passes_through_unchanged(self):
        small = {"positives": 3, "total": 70}
        AnalyzerReport.objects.create(
            cortex_job_id="j-small", type="ip", status="Success", analyzer=self.analyzer,
            ip=self.ip, level="malicious", confidence=90, score=10,
            report_summary={}, report_taxonomy={}, report_full=small,
        )
        result = analyzer_reports_for_prompt(self.case)
        self.assertEqual(result, [{"analyzer": "GTI_Lookup", "report_full": small}])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose --env-file .env run --rm --no-deps suspicious python manage.py test connectors.tests.test_contrib_ai_narration_adapters -v 2` (from `deployment/`)
Expected: `ImportError: cannot import name 'analyzer_reports_for_prompt'` (function doesn't exist yet).

- [ ] **Step 3: Implement `analyzer_reports_for_prompt` in `adapters.py`**

Add to the top of `Suspicious/Suspicious/connectors/contrib/ai_narration/adapters.py` (after the existing module docstring and imports, before `_KNOWN_BANDS`):

```python
import json

_MAX_REPORTS = 20
_MAX_REPORT_FULL_CHARS = 4000


def _cap_report_full(report_full: dict) -> dict:
    serialized = json.dumps(report_full)
    if len(serialized) <= _MAX_REPORT_FULL_CHARS:
        return report_full
    return {
        "_truncated": True,
        "original_size_chars": len(serialized),
        "preview": serialized[:_MAX_REPORT_FULL_CHARS],
    }


def analyzer_reports_for_prompt(case: Case) -> list[dict]:
    """Deduped, capped analyzer_reports ready for build_prompt. Shared by
    the manual test_ai_narration command and the on_case_finalised hook."""
    from api.utils.analyzer_reports import reports_for_case
    from api.views.investigations import _dedup_analyzer_reports

    deduped = _dedup_analyzer_reports(reports_for_case(case))[:_MAX_REPORTS]
    return [
        {"analyzer": r.analyzer.name, "report_full": _cap_report_full(r.report_full)}
        for r in deduped
    ]
```

(The imports of `reports_for_case`/`_dedup_analyzer_reports` stay function-local, matching this module's existing pattern in the file — `case_to_verdict_dict` already imports `Case` at module level since it's used for a type hint, but the API-layer imports here are deliberately deferred to avoid `connectors` importing from `api` at module load time.)

- [ ] **Step 4: Update the management command to use the shared helper**

In `Suspicious/Suspicious/connectors/management/commands/test_ai_narration.py`:

Remove these now-duplicated pieces: the `import json` (keep it — still used for fixture loading), the `_MAX_REPORTS`/`_MAX_REPORT_FULL_CHARS` constants, the `_cap_report_full` function, and the `from api.utils.analyzer_reports import reports_for_case` / `from api.views.investigations import _dedup_analyzer_reports` imports.

Add: `from connectors.contrib.ai_narration.adapters import analyzer_reports_for_prompt, case_to_verdict_dict` (replacing the existing `from connectors.contrib.ai_narration.adapters import case_to_verdict_dict` line).

Replace:
```python
            deduped_reports = _dedup_analyzer_reports(reports_for_case(case))[:_MAX_REPORTS]
            analyzer_reports = [
                {"analyzer": r.analyzer.name, "report_full": _cap_report_full(r.report_full)}
                for r in deduped_reports
            ]
```
with:
```python
            analyzer_reports = analyzer_reports_for_prompt(case)
```

- [ ] **Step 5: Run the new tests, then the full command test file, to verify everything still passes**

Run: `docker compose --env-file .env run --rm --no-deps suspicious python manage.py test connectors.tests.test_contrib_ai_narration_adapters connectors.tests.test_command_ai_narration -v 2` (from `deployment/`)
Expected: PASS, no failures. (`test_command_ai_narration.py` needs no edits — it mocks `select_provider`, not the dedup/cap internals, so the refactor is invisible to it.)

- [ ] **Step 6: Commit**

```bash
git add Suspicious/Suspicious/connectors/contrib/ai_narration/adapters.py \
        Suspicious/Suspicious/connectors/management/commands/test_ai_narration.py \
        Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration_adapters.py
git commit -m "refactor(connectors): extract analyzer_reports_for_prompt into ai_narration adapters"
```

---

### Task 2: Subscribe to `EVENT_CASE_FINALISED`, hardcoded to Ollama

**Files:**
- Modify: `Suspicious/Suspicious/connectors/contrib/ai_narration/connector.py`
- Modify: `Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration.py`

**Interfaces:**
- Consumes: `analyzer_reports_for_prompt` and `case_to_verdict_dict` from Task 1's `adapters.py`; `score_process.scoring.narration.prompt.build_prompt(verdict: dict, analyzer_reports: list[dict]) -> str`; `score_process.scoring.narration.verdict_lock.validate_narration(narration: str, verdict: dict) -> NarrationValidationResult` (has `.passed: bool` and `.reasons: list[str]`, both already used this way in `test_ai_narration.py`); `connectors.contrib.ai_narration.providers.ollama.generate(prompt: str, config: dict) -> str`; `connectors.base.CaseEvent` (fields used: `.status: str`, `.case_id: int`), `connectors.base.EVENT_CASE_FINALISED` (`= "case_finalised"`).
- Produces: `AiNarrationConnector.on_case_finalised(event: CaseEvent) -> None`. Framework-called only (via `connectors/delivery.py`'s `deliver_now`, which already wraps every connector hook with circuit-breaker + retry + `ConnectorDelivery` bookkeeping — untouched by this task).

- [ ] **Step 1: Write the failing tests**

Add to the top of `Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration.py`, alongside the existing imports:

```python
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, ObservableGroup
from connectors.base import CaseEvent, EVENT_CASE_FINALISED
```

Change the existing manifest assertion (it currently asserts no events, which becomes false once this task lands):

```python
    def test_manifest_valid_and_not_enabled_by_default(self):
        m = AiNarrationConnector.manifest
        m.validate()
        self.assertFalse(m.enabled_by_default)
        self.assertEqual(m.events, (EVENT_CASE_FINALISED,))
```

Append this new test class at the end of the file:

```python
def _event(case, status="Done"):
    return CaseEvent(
        event=EVENT_CASE_FINALISED, case_id=case.id, status=status, results=case.results,
        final_score=case.final_score, confidence=case.final_confidence,
        reporter_email="", created_at="2026-09-21T00:00:00+00:00",
    )


class AiNarrationOnCaseFinalisedTest(TestCase):
    def setUp(self):
        reporter = get_user_model().objects.create_user(username="r3", password="x")
        group = ObservableGroup.objects.create(label="g3")
        self.case = Case.objects.create(
            observable_group=group, reporter=reporter, description="",
            results="Dangerous", final_score=9.2, final_confidence=88,
            verdict_explanation={"band": "Dangerous", "confidence": 88, "decisive_rule": "embedded-ioc-escalation"},
        )
        self.connector = AiNarrationConnector({})

    @mock.patch("connectors.contrib.ai_narration.connector.ollama.generate")
    def test_non_done_status_skips_without_calling_provider(self, mock_generate):
        self.connector.on_case_finalised(_event(self.case, status="Ongoing"))
        mock_generate.assert_not_called()

    @mock.patch("connectors.contrib.ai_narration.connector.ollama.generate")
    def test_unknown_band_skips_without_calling_provider(self, mock_generate):
        self.case.results = "Failure"
        self.case.save(update_fields=["results"])
        self.connector.on_case_finalised(_event(self.case, status="Done"))
        mock_generate.assert_not_called()

    @mock.patch("connectors.contrib.ai_narration.connector.ollama.generate")
    def test_happy_path_logs_pass_status_with_narration(self, mock_generate):
        mock_generate.return_value = "This case is Dangerous: an authoritative source confirmed it malicious."
        with self.assertLogs("connectors.contrib.ai_narration", level="INFO") as cm:
            self.connector.on_case_finalised(_event(self.case, status="Done"))
        mock_generate.assert_called_once()
        joined = " ".join(cm.output)
        self.assertIn(f"case={self.case.id}", joined)
        self.assertIn("provider=ollama", joined)
        self.assertIn("status=PASS", joined)

    @mock.patch("connectors.contrib.ai_narration.connector.ollama.generate")
    def test_provider_failure_propagates(self, mock_generate):
        mock_generate.side_effect = RuntimeError("ollama unreachable")
        with self.assertRaises(RuntimeError):
            self.connector.on_case_finalised(_event(self.case, status="Done"))
```

Add `from unittest import mock` if not already imported at the top of the file (it already is, from the existing `AiNarrationHealthCheckTest`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose --env-file .env run --rm --no-deps suspicious python manage.py test connectors.tests.test_contrib_ai_narration -v 2` (from `deployment/`)
Expected: `AttributeError: 'AiNarrationConnector' object has no attribute 'on_case_finalised'` for the new tests (it inherits the base class's `raise NotImplementedError` instead), and the manifest test fails on the `events` assertion.

- [ ] **Step 3: Implement the hook**

In `Suspicious/Suspicious/connectors/contrib/ai_narration/connector.py`:

Update the module docstring (currently says "architecture test only... Not subscribed to any event; drive it via `manage.py test_ai_narration`" — no longer true):

```python
"""AI narration connector. Fires automatically on case finalisation,
hardcoded to local Ollama only (see
docs/specs/2026-09-21-ai-narration-event-wiring-design.md) -- the manual
`manage.py test_ai_narration` command remains available separately for
driving any configured provider (including external ones) against a
specific case or fixture."""
```

Change the imports at the top to add `logging` and the new symbols:

```python
from __future__ import annotations

import logging

import requests

from connectors.base import CaseEvent, Connector, ConnectorManifest, ConfigField, EVENT_CASE_FINALISED, HealthStatus

from .adapters import analyzer_reports_for_prompt, case_to_verdict_dict
from .providers import ollama
from .select import select_provider

logger = logging.getLogger("connectors.contrib.ai_narration")
```

Change the manifest's `description` (append one clause) and `events`:

```python
        description=(
            "Generates a plain-language case narration via a locally-run or "
            "externally-configured LLM, validated against the case's "
            "already-computed verdict. Fires automatically on case "
            "finalisation (Ollama only); manual/fixture-triggered runs via "
            "`manage.py test_ai_narration` can use any configured provider. "
            "See docs/specs/2026-09-21-ai-narration-event-wiring-design.md."
        ),
        ...
        events=(EVENT_CASE_FINALISED,),
```

(Leave `config_schema` and `enabled_by_default=False` exactly as they are — this task changes what the connector does when enabled, not its activation default.)

Add the new method, after `health_check`:

```python
    def on_case_finalised(self, event: CaseEvent) -> None:
        if event.status != "Done":
            return

        from case_handler.models import Case
        from score_process.scoring.narration.prompt import build_prompt
        from score_process.scoring.narration.verdict_lock import validate_narration

        case = Case.objects.get(pk=event.case_id)
        try:
            verdict = case_to_verdict_dict(case)
        except ValueError:
            logger.info(
                "ai_narration: case %s has a band the lock doesn't model, skipping",
                event.case_id,
            )
            return

        analyzer_reports = analyzer_reports_for_prompt(case)
        prompt = build_prompt(verdict, analyzer_reports)
        narration = ollama.generate(prompt, self.config)
        result = validate_narration(narration, verdict)

        logger.info(
            "ai_narration case_finalised: case=%s provider=ollama status=%s "
            "reasons=%s narration=%r",
            event.case_id,
            "PASS" if result.passed else "FAIL",
            result.reasons,
            narration,
        )
```

Note `select_provider` is imported (existing `health_check` already uses it) but never called from `on_case_finalised` — that is the load-bearing property this task must not violate. `ollama.generate` is called directly instead.

While in this file: the existing `except Exception as exc:  # noqa: BLE001 — health check must not raise` comment inside `health_check` has a stray em dash left over from an earlier repo-wide cleanup that didn't reach this exact line — fix it to `# noqa: BLE001 (health check must not raise)` while touching this file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose --env-file .env run --rm --no-deps suspicious python manage.py test connectors.tests.test_contrib_ai_narration connectors.tests.test_contrib_ai_narration_adapters connectors.tests.test_command_ai_narration -v 2` (from `deployment/`)
Expected: PASS, no failures.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/connectors/contrib/ai_narration/connector.py \
        Suspicious/Suspicious/connectors/tests/test_contrib_ai_narration.py
git commit -m "feat(connectors): fire ai_narration on case finalisation, Ollama-only"
```

---

## Final verification (after both tasks)

Run the full backend suite once on the completed branch: `docker compose --env-file .env run --rm --no-deps suspicious python manage.py test` (from `deployment/`, after `docker compose --env-file .env build suspicious` if the image wasn't rebuilt since the last edit — this deployment bakes the image rather than bind-mounting). Expect the pre-existing count plus the 7 tests added across both tasks (3 in Task 1, 4 in Task 2), all green.
