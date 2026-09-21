# AI Narration Event Wiring: Design

## Context

`docs/specs/2026-09-21-ai-narration-connector-design.md` shipped the
`ai_narration` connector as a manual-only architecture test: `events=()`,
driven exclusively by `manage.py test_ai_narration`. That spec's Open
Questions flagged real `on_case_finalised` wiring as contingent on an
unresolved data-governance question — can real case content reach an
external LLM provider automatically.

That question is now answered for the automatic path: **no**. Real events
only ever use local Ollama. External providers (OpenAI/Anthropic/Gemini)
remain available exclusively through the manual command, where a human
explicitly chose to run it against a specific case — that path is
unchanged by this spec.

## Goals

- Subscribe `ai_narration` to `EVENT_CASE_FINALISED` so it fires
  automatically, the same way every other connector in this app does.
- Never let automatic firing reach an external provider — hardcode Ollama
  for this path; `select_provider`'s auto-detection logic is not used here.
- Make the generated narration actually inspectable by a human despite the
  connector framework's `ConnectorDelivery` ledger having no field for
  narration text or validation reasons — log it.
- Reuse everything already built and reviewed: `case_to_verdict_dict`,
  `build_prompt`, `validate_narration`, the dedup+cap logic from the manual
  command (extracted into a shared helper so both call sites use one
  implementation).

## Non-goals

- No report/email/UI rendering of narration — still ledger/log-only.
- No change to the manual `test_ai_narration` command's own behavior
  (still all four providers, still requires an explicit human invocation)
  beyond the refactor that extracts its dedup+cap logic into a shared
  helper.
- No change to `select.py`'s auto-detection logic — it remains exactly as
  built, simply unused by the event-driven path.
- Prompt injection from real case content (a phishing email's own text
  reaching the LLM prompt) is not newly introduced by this spec — it
  already exists in the manual `--case-id` path — but automatic firing
  means it now happens without a human choosing to run it that specific
  time. Blast radius stays a log line, not a rendered surface, which is
  why this is accepted rather than blocking on it; it remains a
  precondition for any future report/email/UI phase (see the connector
  spec's Open Questions).

## Architecture

One new method on the existing `Connector` subclass, one shared helper
extracted from existing code, no new modules.

1. **`connectors/contrib/ai_narration/adapters.py`** gains
   `analyzer_reports_for_prompt(case) -> list[dict]` — the dedup+cap logic
   currently inlined in `test_ai_narration.py`, moved here so both the
   manual command and the new event hook use one implementation.
2. **`connectors/contrib/ai_narration/connector.py`** — manifest gains
   `events=(EVENT_CASE_FINALISED,)`; the class gains `on_case_finalised`.
   The framework (`connectors/delivery.py`'s `deliver_now`, unchanged)
   already wraps this call with circuit-breaker protection, retries, and
   `ConnectorDelivery` bookkeeping — the hook itself writes nothing to the
   ledger directly, exactly like every other connector's hook.

## Components

### `connectors/contrib/ai_narration/adapters.py` (addition)

```python
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
    from api.views.investigations import _dedup_analyzer_reports
    from api.utils.analyzer_reports import reports_for_case

    deduped = _dedup_analyzer_reports(reports_for_case(case))[:_MAX_REPORTS]
    return [
        {"analyzer": r.analyzer.name, "report_full": _cap_report_full(r.report_full)}
        for r in deduped
    ]
```

(`_cap_report_full` and `_MAX_REPORTS`/`_MAX_REPORT_FULL_CHARS` move here
verbatim from `test_ai_narration.py`, which is updated to import
`analyzer_reports_for_prompt` instead of building the list inline.)

### `connectors/contrib/ai_narration/connector.py` (addition)

```python
import logging

from connectors.base import CaseEvent, EVENT_CASE_FINALISED

logger = logging.getLogger("connectors.contrib.ai_narration")

# manifest gains: events=(EVENT_CASE_FINALISED,)

    def on_case_finalised(self, event: CaseEvent) -> None:
        if event.status != "Done":
            return

        from case_handler.models import Case
        from score_process.scoring.narration.prompt import build_prompt
        from score_process.scoring.narration.verdict_lock import validate_narration
        from .adapters import analyzer_reports_for_prompt, case_to_verdict_dict
        from .providers import ollama

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

Note the deliberate choices here:
- `select_provider` is never imported or called — `ollama.generate` is
  called directly. There is no config path that can make this hook reach
  an external provider.
- An out-of-vocabulary band (`ValueError` from `case_to_verdict_dict`)
  returns quietly rather than propagating — matches how
  `SmtpNotifyConnector.on_case_finalised` already treats "this case type
  doesn't apply to me" (e.g. its own `fileOrMail is None` / missing
  `MailInfo` checks), not a connector-level failure. This keeps the
  `ConnectorDelivery` ledger meaningful: `Failure`/`AllowListed`/etc. band
  cases show as ordinary successes (nothing to do), not false failures.
- A genuine failure (Ollama unreachable, HTTP error from `ollama.generate`,
  a `Case.DoesNotExist`) is allowed to propagate uncaught — `deliver_now`
  catches it, records `ConnectorDelivery(status=failed, error=...)`, and
  retries up to `MAX_ATTEMPTS` with backoff, identically to every other
  connector's hook. No new error-handling code needed here.

## Data Flow

```
finalise(case) -> emit_connector_event("case_finalised", case)
  -> connectors.dispatch.emit -> (only if ConnectorState.enabled)
  -> connectors.tasks.deliver_event (Celery, async, on_commit)
  -> connectors.delivery.deliver_now
       -> AiNarrationConnector.on_case_finalised(event)
            -> case_to_verdict_dict(case)            [skip if ValueError]
            -> analyzer_reports_for_prompt(case)
            -> build_prompt(verdict, analyzer_reports)
            -> providers.ollama.generate(prompt, config)  [always ollama]
            -> validate_narration(narration, verdict)
            -> logger.info(...)                       [human-inspectable]
       -> ConnectorDelivery row (success/failed, framework-managed)
```

## Error Handling

Unchanged from the framework's existing, already-battle-tested behavior
for every connector — nothing new to specify:
- Exception in the hook → `ConnectorDelivery(status=failed)`, retried up
  to `MAX_ATTEMPTS` with exponential backoff (`connectors/delivery.py`,
  untouched by this spec).
- Circuit breaker trips after repeated failures → further deliveries
  `STATUS_SKIPPED` until it resets (`common/http_client.get_breaker`,
  already wired for every registered connector at registration time).
- Connector disabled → `dispatch.emit` never selects it as a subscriber;
  nothing happens, no ledger row at all.

## Testing

- `analyzer_reports_for_prompt` / `_cap_report_full`: move the existing
  dedup/cap tests from `test_command_ai_narration.py` (added in the prior
  fix wave) to `test_contrib_ai_narration_adapters.py`, since the logic
  moved there. No behavior change, so no new test cases — same coverage,
  relocated.
- `on_case_finalised`: new tests in `test_contrib_ai_narration.py` —
  - `event.status != "Done"` → hook returns immediately, `ollama.generate`
    never called (mock asserts `assert_not_called`).
  - Case band not in the known vocabulary → hook returns without raising,
    `ollama.generate` never called.
  - Happy path → `ollama.generate` mocked to return narration text,
    asserts the log message is emitted (via `self.assertLogs`) with the
    expected case id, provider, and PASS/FAIL status. `select_provider` /
    external providers are asserted never imported or called — the
    cleanest check is that no test in this file ever needs to mock
    `openai`/`anthropic`/`gemini`, because the hook has no code path that
    reaches them.
  - Provider raises → the hook lets the exception propagate uncaught
    (assert via `self.assertRaises`, not via checking a `ConnectorDelivery`
    row — ledger-writing is the framework's job, already tested by
    `connectors/tests/test_dispatch.py` and `test_models.py`, not
    something this task re-tests).
- Registration test (`test_registered_as_a_builtin`, already existing)
  needs no change — the manifest's `events` value is covered by a new
  assertion in the existing manifest test:
  `self.assertEqual(m.events, (EVENT_CASE_FINALISED,))`.

## Open Questions / Follow-on Work (not in this spec)

- Report/email/UI rendering — still contingent on resolving the
  prompt-injection concern for a real reader-facing surface, unchanged
  from the connector spec's own Open Questions.
- Whether the automatic path should also run against `EVENT_CASE_CREATED`
  or only finalization — not requested, not speced here.
- If external providers are ever wanted on the automatic path, that is a
  distinct, separate data-governance decision this spec explicitly does
  NOT make — it hardcodes local-only and provides no configuration
  surface to change that.
