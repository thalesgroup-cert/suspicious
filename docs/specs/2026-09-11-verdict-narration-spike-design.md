# Verdict Narration Spike: Design

## Context

The SOC roadmap's P4 item calls for a rich, plain-language case report for
non-technical stakeholders, synthesizing all analyzer reports (VT, GTI, MISP,
etc.) plus the AI_Mail_Analyzer's output for mail cases. The original proposal
was to teacher-distil a hosted LLM into a fine-tuned open-weight model
(Qwen2.5-7B-Instruct via LoRA/QLoRA) for on-prem deployment.

That proposal went through an LLM Council pressure-test
(`docs/research/2026-09-11-verdict-narration-council-*`). The council's
unanimous recommendation: don't start the training pipeline. Build the
verdict-lock safety mechanism first (needed under any architecture), and
prompt an already-available on-prem instruct model before investing in
training at all — the fine-tune may turn out to be unnecessary.

This spec covers exactly that first step, and nothing past it. It is
deliberately small.

## Goals

- Build the deterministic safety mechanism ("verdict lock") that any future
  narration approach — prompted or fine-tuned — will need: the case's
  band/score/confidence are injected as fixed, literal facts and never
  authored by the model, and generated narration is validated against those
  facts before anyone sees it.
- Answer, with real (synthetic) evidence: is a locally-run 7B instruct model,
  simply prompted with case facts and analyzer reports, good enough at
  producing a non-technical narrative to make training unnecessary?

## Non-goals

- No training/fine-tuning pipeline, teacher distillation, or dataset
  generation. That is only worth speccing if this spike's output is judged
  inadequate.
- No wiring into the live case-finalization path, no UI/report/email
  rendering of narration output, no Cortex-analyzer packaging. Those are
  follow-on specs, contingent on this spike succeeding.
- No use of real case data. Fixtures are hand-written, synthetic, and
  realistic only in shape (fake domains, fake headers, fake IOCs) — chosen
  specifically so this spike doesn't have to wait on a data-classification
  decision for real CERT case content.

## Architecture

A standalone harness, decoupled from the scoring pipeline. Two parts:

1. **`verdict_lock`** — a deterministic module. Given a case's already-computed
   verdict (`CaseVerdict` for mail, `GroupVerdict`/`ObservableVerdict` for the
   IOC road — the same dataclasses introduced by the verdict-explanation
   feature in `score_process/scoring/explanation/types.py` and
   `observable_engine.py`/`engine.py`), it:
   - renders a literal, non-model-authored block of facts (band, score,
     confidence, decisive rule) to include in the prompt, and
   - validates a candidate narration string after generation, checking it
     doesn't assert a different band, score, or confidence than the facts it
     was given.
2. **`narration_spike`** — a Django management command that drives the actual
   experiment: load a synthetic case fixture, build a prompt (case facts +
   full analyzer `report_full` payloads, in the same shape the
   verdict-explanation adapters already consume), call a locally-running
   Ollama server serving Qwen2.5-7B-Instruct, run the result through
   `verdict_lock.validate_narration`, and write a labeled result to a file
   for manual review.

## Components

### `score_process/scoring/narration/verdict_lock.py`

```python
@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    reasons: list[str]  # empty when passed

def render_fixed_facts(verdict) -> str:
    """Literal block: band, score, confidence, decisive rule. Never
    produced by the model — always injected verbatim into the prompt."""

def validate_narration(text: str, verdict) -> ValidationResult:
    """Fails if `text` contains a band word from the real band vocabulary
    ("Safe", "Suspicious", "Dangerous", "Inconclusive" — see
    `observable_engine.py`'s `_BAND_ORDER`) other than `verdict`'s own band,
    or a numeric score/confidence that doesn't match. Passes if the text
    mentions no competing verdict language at all (silence is not a
    contradiction)."""
```

### `score_process/scoring/narration/prompt.py`

```python
def build_prompt(verdict, analyzer_reports: list[dict]) -> str:
    """Fixed-facts block (from render_fixed_facts) + full analyzer report
    payloads + instructions to narrate for a non-technical reader without
    restating or second-guessing the verdict."""
```

### `score_process/management/commands/narration_spike.py`

CLI: `manage.py narration_spike <fixture_path> [--ollama-url URL] [--model NAME]`

- Loads the fixture JSON (case verdict facts + analyzer reports).
- Calls `build_prompt`, POSTs to Ollama's `/api/generate` (default
  `http://localhost:11434`, model `qwen2.5:7b-instruct`).
- Runs the response through `validate_narration`.
- Writes `<fixture>.result.txt`: `PASS`/`FAIL`, the reasons if failed, and
  the full raw narration text, for a human to read.

### `docs/research/fixtures/*.json`

Hand-written synthetic cases, one per fixture, covering:
- Mail road: Safe, Suspicious, Dangerous bands (varying `AI_Mail_Analyzer`
  confidence and 2-3 supporting/contradicting analyzer reports each).
- IOC road: Safe, Suspicious, Dangerous bands (single-observable and
  multi-observable group cases).

Each fixture is a plain JSON file: `{"verdict": {...}, "analyzer_reports":
[...]}`, matching the field names `verdict_lock` and `prompt` expect.

## Data Flow

```
fixture.json
  -> narration_spike loads verdict + analyzer_reports
  -> prompt.build_prompt() [fixed-facts block always first, literal]
  -> POST to Ollama (Qwen2.5-7B-Instruct)
  -> raw narration text
  -> verdict_lock.validate_narration()
  -> fixture.result.txt (PASS/FAIL + narration, for manual read)
```

## Error Handling

- Ollama unreachable or times out: the command exits non-zero with the HTTP
  error surfaced directly. No silent fallback — this is a spike meant to
  surface problems, not paper over them.
- Validation failure: still write the raw narration to the result file,
  labeled `FAIL` with the specific reason(s), so the failure mode itself is
  inspectable rather than swallowed.
- Malformed fixture (missing required fields): fail fast with a clear
  `KeyError`-derived message naming the missing field.

## Testing

Unit tests for `verdict_lock.validate_narration` (no network, no Ollama
dependency):
- Narration stating the correct band/score → `passed=True`.
- Narration stating a *different* band than the injected verdict → `passed=False`,
  with a reason naming the contradicting band.
- Narration with no verdict language at all (pure description) → `passed=True`
  (omission is not a contradiction).
- Narration with a fabricated confidence percentage that doesn't match the
  injected value → `passed=False`.

One smoke test for `narration_spike` against a mocked Ollama HTTP response,
verifying the result file is written with the expected PASS/FAIL shape — no
live model call in CI.

No automated test of actual narration *quality* — that judgment is manual,
by design: an analyst reads the `.result.txt` files and reports back whether
the output is good enough to make training unnecessary. That verdict is this
spike's actual deliverable, not a passing test suite.

## Open Questions / Follow-on Work (not in this spec)

- If the spike output is judged good enough: spec the integration into case
  finalization, report/email/UI rendering, and likely packaging as a Cortex
  analyzer (matching the AIMailAnalyzer deployment pattern already used in
  this codebase).
- If judged inadequate: revisit teacher distillation, but only after the
  data-governance question the council raised (can real case content be sent
  to a hosted teacher API at all) is resolved on its own — not decided by
  default because a spike happened to work around it with synthetic data.
- Standing up Ollama itself (install, model pull, resource sizing) is
  environment setup, tracked in the implementation plan, not a design
  decision.
