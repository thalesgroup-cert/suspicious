# Verdict Explanation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** At case finalization, build one structured `VerdictExplanation` from whichever scoring engine ran, store it on the `Case`, and render it in the investigation UI, the downloadable report (analyst view), and the reporter email (plain-language view).

**Architecture:** A new `score_process/scoring/explanation/` package: a `VerdictExplanation` dataclass (`types.py`), a rule-based text `compose()` (`compose.py`), and one adapter per engine (`adapters.py`). Each engine's result object gains a `rule: str` key naming the decision that fired; the adapters turn `(engine result, analyzer reports)` into a `VerdictExplanation`. Stored on `Case.verdict_explanation` (JSONField), rendered by the serializer / report template / email context. Read-only over the verdict — changes no band, score, or confidence.

**Tech Stack:** Django 6.1, Python 3.12, DRF, Jinja2 (reporter emails), Frozen dataclasses. Frontend: React 19 + TypeScript + MUI v9 + Zod. No new dependency.

**Spec:** `docs/specs/2026-09-10-verdict-explanation-design.md`

## Global Constraints

- **No new dependency.** Rule-based composition only; no LLM, no generated text.
- **No change to any band, score, or confidence.** The explanation is derived from the already-computed verdict. `python manage.py backtest_scoring` must show zero verdict drift.
- **Explanation failure must never block finalization** — wrap adapter/compose calls in `try/except`, log, leave `verdict_explanation` null (same discipline as the screenshot capture path in `score_process/scoring/cortex_analyzers/reports.py`).
- **Every surface falls back when `verdict_explanation` is null**: report + UI → the existing `verdict_rationale` bullets; email → the existing `_RESULT_GUIDANCE[band]`.
- English only (matches the codebase — `USE_I18N=True` but zero `gettext`).
- `decisive_rule` is a **closed enum**; an unknown value must render a generic template, never raise.
- Tests run through `ww-test backend --project suspicious <labels>` / `ww-test frontend --project suspicious`. Django project is nested at `Suspicious/Suspicious/` — `manage.py` paths are relative to there; `git add` paths in this plan are worktree-relative (prefixed `Suspicious/Suspicious/`).
- Conventional Commits, explicit `git add <paths>` (never `-A`), commit after every task. **No `Co-Authored-By: Claude` / `Claude-Session:` trailers** (public repo).
- After a containerised backend test run, remove any stray root-owned `Suspicious/Suspicious/gunicorn.conf.py` before committing.

---

## The `decisive_rule` enum (closed set)

**Categorical engine** (`score_observable` branches, `apply.py` reconstructions):
`tier1-authoritative-malicious` · `tier2-consensus-malicious` · `weighted-malicious-share` · `tier1-authoritative-clean` · `trusted-flag-not-decisive` · `contextual-only-flag` · `no-flag` · `thin-coverage` · `deny-listed` · `derived-observable-escalation` · `group-worst-of`

**Weighted engine** (`score_case` → `_classify_rule`):
`weighted-consensus` · `single-strong-signal` · `embedded-ioc-escalation` · `ai-classifier-decisive` · `deny-listed` · `no-signal` · `analysis-incomplete`

Plus the sentinel `unknown` (generic template).

---

## File Structure

### Backend (all under `Suspicious/Suspicious/`)

| File | Responsibility |
|---|---|
| `score_process/scoring/explanation/__init__.py` | package marker |
| `score_process/scoring/explanation/types.py` | `SourceLine`, `VerdictExplanation` dataclasses + `to_dict()` |
| `score_process/scoring/explanation/compose.py` | `_RULE_TEMPLATES`, `_CONFIDENCE_READINGS`, `_RECOMMENDATION`, `compose()` |
| `score_process/scoring/explanation/adapters.py` | `explain_observable_group()`, `explain_mail_case()` |
| `score_process/scoring/observable_engine.py` | `ObservableVerdict.rule`, `GroupVerdict.rule`; set at each `return` |
| `score_process/scoring/engine.py` | `CaseVerdict.rule`; `_classify_rule()` |
| `score_process/scoring/apply.py` | pass `rule` in the deny-list / derived reconstructions; call `explain_observable_group` in `finalise_ioc_group`; accept `explanation=` in `apply_verdict` |
| `score_process/scoring/cortex_analyzers/reports.py` | build the mail `VerdictExplanation`, pass to `apply_verdict` |
| `case_handler/models.py` + migration | `Case.verdict_explanation` JSONField |
| `score_process/management/commands/backfill_verdict_explanation.py` | **new** — backfill |
| `api/serializers/investigations.py` | `verdict_explanation` on the investigation detail |
| `templates/case_report/report.html` | "Why this verdict" block |
| `score_process/score_utils/send_mail/final_service.py` + `modification_service.py` | `reporter_paragraph` into the email context |
| `score_process/score_utils/send_mail/templates/final_email.jinja2` + `modification_email.jinja2` | render it |

### Frontend

| File | Responsibility |
|---|---|
| `suspicious-ui/src/features/investigation/VerdictExplanation.tsx` | **new** — paragraph + confidence reading + toggled source table |
| `suspicious-ui/src/features/investigation/api.ts` | `verdict_explanation` type on `InvestigationDetails` |
| `suspicious-ui/src/pages/InvestigationPage.tsx` (or the layout component that shows the verdict) | render `<VerdictExplanation>` |

---

## Task 1: `VerdictExplanation` + `SourceLine` types

**Files:**
- Create: `Suspicious/Suspicious/score_process/scoring/explanation/__init__.py` (empty)
- Create: `Suspicious/Suspicious/score_process/scoring/explanation/types.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_explanation_types.py`

**Interfaces:**
- Produces:
  - `SourceLine(name: str, tier: int, verdict: str, counted: bool, note: str)` — frozen dataclass
  - `VerdictExplanation(band, confidence, decisive_rule, analyst_paragraph, reporter_paragraph, confidence_reading, sources)` — frozen dataclass; `sources: tuple[SourceLine, ...]`
  - `VerdictExplanation.to_dict() -> dict` — JSON-safe (`sources` as list of dicts)

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_explanation_types.py
from django.test import SimpleTestCase
from score_process.scoring.explanation.types import SourceLine, VerdictExplanation


class ExplanationTypesTest(SimpleTestCase):
    def _ve(self):
        return VerdictExplanation(
            band="Dangerous", confidence=90, decisive_rule="tier1-authoritative-malicious",
            analyst_paragraph="A.", reporter_paragraph="R.", confidence_reading="C.",
            sources=(SourceLine("GTI", 1, "malicious", True, "trojan"),
                     SourceLine("DShield", 3, "no-data", False, "")),
        )

    def test_to_dict_is_json_safe(self):
        import json
        d = self._ve().to_dict()
        json.dumps(d)  # must not raise
        self.assertEqual(d["band"], "Dangerous")
        self.assertEqual(d["sources"][0], {"name": "GTI", "tier": 1, "verdict": "malicious",
                                           "counted": True, "note": "trojan"})
        self.assertEqual(len(d["sources"]), 2)

    def test_frozen(self):
        with self.assertRaises(Exception):
            self._ve().band = "Safe"
```

- [ ] **Step 2: Run to verify it fails**

Run: `ww-test backend --project suspicious score_process.tests.test_explanation_types`
Expected: FAIL — `ModuleNotFoundError: score_process.scoring.explanation`

- [ ] **Step 3: Implement**

```python
# score_process/scoring/explanation/types.py
"""Structured, render-agnostic explanation of a case verdict.
Read-only over the scoring output — carries no verdict logic."""
from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class SourceLine:
    name: str
    tier: int          # 1 authoritative / 2 strong / 3 contextual / 0 untiered
    verdict: str        # malicious | suspicious | clean | no-data | failed
    counted: bool       # did this source feed the decisive rule?
    note: str = ""


@dataclass(frozen=True)
class VerdictExplanation:
    band: str
    confidence: int
    decisive_rule: str
    analyst_paragraph: str
    reporter_paragraph: str
    confidence_reading: str
    sources: tuple[SourceLine, ...] = ()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["sources"] = [asdict(s) for s in self.sources]
        return d
```

- [ ] **Step 4: Run tests**

Run: `ww-test backend --project suspicious score_process.tests.test_explanation_types`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/explanation/ Suspicious/Suspicious/score_process/tests/test_explanation_types.py
git commit -m "feat(explanation): VerdictExplanation + SourceLine types"
```

---

## Task 2: The composer

**Files:**
- Create: `Suspicious/Suspicious/score_process/scoring/explanation/compose.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_explanation_compose.py`

**Interfaces:**
- Consumes: `SourceLine` (Task 1)
- Produces: `compose(rule: str, band: str, confidence: int, sources: list[SourceLine], **facts) -> tuple[str, str, str]` returning `(analyst_paragraph, reporter_paragraph, confidence_reading)`
- `**facts` keys used by templates: `source` (str, the decisive analyzer name), `n_context` (int), `n_counted` (int), `n_total` (int), `share` (float 0–1), `data_type` (str), `missing` (str, for thin-coverage / analysis-incomplete)

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_explanation_compose.py
import re
from django.test import SimpleTestCase
from score_process.scoring.explanation.compose import compose, RULE_KEYS
from score_process.scoring.explanation.types import SourceLine

FACTS = dict(source="GTI", n_context=2, n_counted=1, n_total=3, share=0.67,
             data_type="url", missing="no authoritative source ran")


class ComposeTest(SimpleTestCase):
    def test_every_rule_key_composes_fully(self):
        for rule in RULE_KEYS:
            a, r, c = compose(rule, "Dangerous", 80, [SourceLine("GTI", 1, "malicious", True, "")], **FACTS)
            for text in (a, r, c):
                self.assertTrue(text.strip(), f"{rule}: empty text")
                self.assertNotRegex(text, r"\{[a-z_]+\}", f"{rule}: unfilled placeholder in {text!r}")

    def test_unknown_rule_is_generic_not_raising(self):
        a, r, c = compose("nonsense-rule", "Suspicious", 50, [], **FACTS)
        self.assertIn("Suspicious", a)

    def test_safe_low_confidence_special_reading(self):
        _, _, c = compose("no-flag", "Safe", 20, [], **FACTS)
        self.assertIn("does not mean", c.lower())

    def test_strong_confidence_reading(self):
        _, _, c = compose("tier1-authoritative-malicious", "Dangerous", 95, [], **FACTS)
        self.assertRegex(c.lower(), r"strong|high")
```

- [ ] **Step 2: Run to verify it fails**

Run: `ww-test backend --project suspicious score_process.tests.test_explanation_compose`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement**

```python
# score_process/scoring/explanation/compose.py
"""Rule-based composition of the analyst + reporter explanation text.
No generated text — parameterised sentence templates keyed on the decisive rule."""
from __future__ import annotations

_RECOMMENDATION = {
    "Dangerous": "Do not interact with it; contact your security team if you already did.",
    "Suspicious": "Avoid interacting with any files or links until the review completes.",
    "Safe": "No threat was found, but stay vigilant — no analysis is fully conclusive.",
    "Inconclusive": "Treat the item with caution until a human review completes.",
}

# rule -> {"analyst": template, "reporter": template}
_RULE_TEMPLATES = {
    "tier1-authoritative-malicious": {
        "analyst": "{source} is an authoritative threat-intelligence source and reported "
                   "this {data_type} malicious — that determines the verdict on its own. "
                   "{n_context} other source(s) were consulted for context.",
        "reporter": "This was confirmed malicious by a trusted threat-intelligence source.",
    },
    "tier2-consensus-malicious": {
        "analyst": "{n_counted} independent strong sources agree this {data_type} is "
                   "malicious.",
        "reporter": "Multiple independent security sources flagged this as malicious.",
    },
    "weighted-malicious-share": {
        "analyst": "The trust-weighted share of sources calling this malicious is "
                   "{share:.0%}, past the threshold for Dangerous.",
        "reporter": "The weight of evidence points to this being malicious.",
    },
    "tier1-authoritative-clean": {
        "analyst": "{source} (authoritative) reports this {data_type} clean and no source "
                   "contradicts it.",
        "reporter": "A trusted threat-intelligence source reports this is not a threat.",
    },
    "trusted-flag-not-decisive": {
        "analyst": "{source} flags this {data_type}, but the evidence is not strong enough "
                   "for a malicious verdict — capped at Suspicious.",
        "reporter": "A security source raised a concern, but it is not confirmed malicious.",
    },
    "contextual-only-flag": {
        "analyst": "Only low-trust / contextual sources flag this {data_type}; the verdict "
                   "is capped at Suspicious.",
        "reporter": "A lower-confidence source raised a concern about this item.",
    },
    "no-flag": {
        "analyst": "No source flags this {data_type}.",
        "reporter": "No security source flagged this item.",
    },
    "thin-coverage": {
        "analyst": "The verdict is Inconclusive: {missing}. There is not enough signal to "
                   "assess this {data_type}.",
        "reporter": "The analyzers could not reach a definitive verdict on this item.",
    },
    "deny-listed": {
        "analyst": "This indicator is on the organisation deny list, which forces a "
                   "Dangerous verdict.",
        "reporter": "This item matches your organisation's block list.",
    },
    "derived-observable-escalation": {
        "analyst": "An observable extracted from this one scored worse and raised the "
                   "verdict to {band}.",
        "reporter": "Something this item leads to was found to be a threat.",
    },
    "group-worst-of": {
        "analyst": "{n_counted} of {n_total} submitted indicator(s) are {band}; the case "
                   "takes the worst.",
        "reporter": "At least one of the submitted indicators is {band}.",
    },
    "weighted-consensus": {
        "analyst": "The trust-weighted average of {n_counted} analyzer result(s) puts this "
                   "case at {band}.",
        "reporter": "The overall weight of the analysis puts this at {band}.",
    },
    "single-strong-signal": {
        "analyst": "One analyzer result carried enough confidence to set the verdict at "
                   "{band}.",
        "reporter": "One part of the analysis was decisive for this verdict.",
    },
    "embedded-ioc-escalation": {
        "analyst": "An indicator embedded in this message scored {band}, which raised the "
                   "case band.",
        "reporter": "A link or attachment in this message was found to be a threat.",
    },
    "ai-classifier-decisive": {
        "analyst": "The AI phishing classifier was the highest-confidence signal and set "
                   "the verdict at {band}.",
        "reporter": "Automated phishing detection was decisive for this verdict.",
    },
    "no-signal": {
        "analyst": "No analyzer flagged anything in this message.",
        "reporter": "No security check flagged this message.",
    },
    "analysis-incomplete": {
        "analyst": "The verdict is Inconclusive: {missing}.",
        "reporter": "The analysis could not be completed for a definitive verdict.",
    },
}

RULE_KEYS = tuple(_RULE_TEMPLATES)

_GENERIC = {
    "analyst": "The verdict is {band}, based on {n_counted} of {n_total} source(s).",
    "reporter": "The analysis result is {band}.",
}


def _confidence_reading(band: str, confidence: int) -> str:
    if band == "Safe" and confidence < 40:
        return ("A low risk score with low confidence does not mean the item is safe — it "
                "means the analyzers could not gather enough signal to be sure. Treat it "
                "as unconfirmed.")
    if confidence >= 70:
        return f"Confidence {confidence}/100: strong corroboration across sources."
    if confidence >= 40:
        return f"Confidence {confidence}/100: moderate corroboration; treat as likely but not certain."
    return f"Confidence {confidence}/100: limited corroboration; treat this verdict as provisional."


def _fill(tmpl: str, band: str, confidence: int, sources, facts: dict) -> str:
    ctx = {"band": band, "confidence": confidence,
           "source": facts.get("source", "a source"),
           "n_context": facts.get("n_context", 0),
           "n_counted": facts.get("n_counted", sum(1 for s in sources if s.counted)),
           "n_total": facts.get("n_total", len(sources)),
           "share": facts.get("share", 0.0),
           "data_type": facts.get("data_type", "indicator"),
           "missing": facts.get("missing", "coverage is thin")}
    return tmpl.format(**ctx)


def compose(rule, band, confidence, sources, **facts):
    t = _RULE_TEMPLATES.get(rule, _GENERIC)
    reading = _confidence_reading(band, confidence)
    analyst = _fill(t["analyst"], band, confidence, sources, facts) + " " + reading
    reporter = _fill(t["reporter"], band, confidence, sources, facts) + " " + \
        _RECOMMENDATION.get(band, _RECOMMENDATION["Inconclusive"])
    return analyst, reporter, reading
```

- [ ] **Step 4: Run tests**

Run: `ww-test backend --project suspicious score_process.tests.test_explanation_compose`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/explanation/compose.py Suspicious/Suspicious/score_process/tests/test_explanation_compose.py
git commit -m "feat(explanation): rule-based analyst + reporter text composer"
```

---

## Task 3: `rule` key on the categorical engine

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/observable_engine.py` — add `rule: str = ""` to `ObservableVerdict` and `GroupVerdict`; set it at every `return`
- Modify: `Suspicious/Suspicious/score_process/scoring/apply.py` — the two `ObservableVerdict(...)` reconstructions in `finalise_ioc_group` pass a rule
- Test: `Suspicious/Suspicious/score_process/tests/test_explanation_engine_rules.py`

**Interfaces:**
- Produces: `ObservableVerdict.rule` and `GroupVerdict.rule` — one of the categorical enum keys (see top of plan). Existing positional constructions keep working (`rule` is last, defaulted).

**Rule mapping** (read `score_observable` — each branch already appends a matching rationale string):
| branch condition | `rule` |
|---|---|
| `t1_mal` (tier-1 malicious) → Dangerous | `tier1-authoritative-malicious` |
| ≥2 tier-2 malicious → Dangerous | `tier2-consensus-malicious` |
| weighted malicious share over threshold → Dangerous | `weighted-malicious-share` |
| tier-1 clean, nothing contradicts → Safe | `tier1-authoritative-clean` |
| trusted source flags, not decisive → Suspicious | `trusted-flag-not-decisive` |
| only contextual flags → Suspicious | `contextual-only-flag` |
| nothing flags → Safe | `no-flag` |
| thin coverage → Inconclusive | `thin-coverage` |
- `score_group` → `rule="group-worst-of"` (both the assessed and the all-inconclusive return).
- `apply.py` deny-list reconstruction → `rule="deny-listed"`; derived-escalation reconstruction → `rule="derived-observable-escalation"`.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_explanation_engine_rules.py
from django.test import SimpleTestCase
from score_process.scoring.observable_engine import score_observable, score_group
from score_process.scoring.sources import SourceVerdict


def sv(name, tier, verdict, conf=80):
    return SourceVerdict(name=name, tier=tier, weight=0.2, verdict=verdict,
                         confidence=conf, failed=False, evidence="")


class EngineRuleTest(SimpleTestCase):
    def test_tier1_malicious_rule(self):
        v = score_observable([sv("GTI", 1, "malicious")])
        self.assertEqual(v.band, "Dangerous")
        self.assertEqual(v.rule, "tier1-authoritative-malicious")

    def test_no_flag_rule(self):
        v = score_observable([sv("X", 3, "clean")])
        self.assertEqual(v.rule, "tier1-authoritative-clean" if v.band == "Safe" else v.rule)

    def test_nothing_rule(self):
        v = score_observable([])
        self.assertEqual(v.rule, "thin-coverage")

    def test_group_rule(self):
        g = score_group([score_observable([sv("GTI", 1, "malicious")])])
        self.assertEqual(g.rule, "group-worst-of")
```

> Adjust the expected `rule` values to the branch each fixture actually hits — read `score_observable` first and pick fixtures that land squarely on one branch.

- [ ] **Step 2: Run to verify it fails**

Run: `ww-test backend --project suspicious score_process.tests.test_explanation_engine_rules`
Expected: FAIL — `AttributeError: 'ObservableVerdict' object has no attribute 'rule'`

- [ ] **Step 3: Implement**

Add `rule: str = ""` as the last field of both dataclasses. At each `return ObservableVerdict(...)` / `return GroupVerdict(...)`, pass the key from the mapping table (keyword arg `rule=...` to avoid positional drift). In `apply.py`, the two reconstructions become e.g.:

```python
v = ObservableVerdict("Dangerous", 100, None, v.counts,
                      list(v.rationale) + [f"Indicator is on the deny list ({matched})."],
                      rule="deny-listed")
```

- [ ] **Step 4: Run tests**

Run: `ww-test backend --project suspicious score_process`
Expected: PASS (full `score_process` — existing engine tests must stay green)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/observable_engine.py Suspicious/Suspicious/score_process/scoring/apply.py Suspicious/Suspicious/score_process/tests/test_explanation_engine_rules.py
git commit -m "feat(explanation): name the decisive rule on the categorical engine"
```

---

## Task 4: `rule` key on the weighted engine

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/engine.py` — add `rule: str = ""` to `CaseVerdict`; add `_classify_rule(...)`; set `rule` on every `CaseVerdict(...)` return; `mail_band_escalation` sets `rule="embedded-ioc-escalation"` when it raises the band
- Test: `Suspicious/Suspicious/score_process/tests/test_explanation_weighted_rule.py`

**Interfaces:**
- Consumes: nothing new
- Produces: `CaseVerdict.rule` — one of the weighted enum keys. `_classify_rule(scored, n_malicious, n_scored, final_score, final_conf, ai, ai_missing, worst, wmean) -> str`.

**Mapping** (read `score_case`):
| condition | rule |
|---|---|
| `deny_listed` return | `deny-listed` |
| `not scored` (Failure) return | `analysis-incomplete` |
| `ai is not None and ai.confidence > base_conf` (AI override) | `ai-classifier-decisive` |
| `ai_missing` → Inconclusive | `analysis-incomplete` |
| `final_score == NEUTRAL or final_conf < CONF_FLOOR` → Inconclusive | `analysis-incomplete` |
| `worst > wmean` (the `max()` picked the single strong signal) | `single-strong-signal` |
| result is Safe and nothing flagged (`n_malicious == 0` and `final_score` low) | `no-signal` |
| otherwise | `weighted-consensus` |
- `mail_band_escalation`: when it raises the band, return a `CaseVerdict` copy with `rule="embedded-ioc-escalation"`; when it doesn't raise the band but records the `note`, keep the incoming `rule`.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_explanation_weighted_rule.py
from django.test import SimpleTestCase
from score_process.scoring.engine import score_case
# reuse whatever signal factory the existing engine tests use — see
# score_process/tests/test_*engine*.py / test_score_case*.py for `Signal` construction


class WeightedRuleTest(SimpleTestCase):
    def test_deny_listed_rule(self):
        v = score_case([], deny_listed=True, deny_reason="x")
        self.assertEqual(v.rule, "deny-listed")

    def test_no_scored_rule(self):
        v = score_case([])
        self.assertEqual(v.rule, "analysis-incomplete")
    # + one test each for weighted-consensus / single-strong-signal / no-signal
    #   using real Signal fixtures from the existing engine test module
```

- [ ] **Step 2: Run to verify it fails**

Run: `ww-test backend --project suspicious score_process.tests.test_explanation_weighted_rule`
Expected: FAIL — `AttributeError: 'CaseVerdict' object has no attribute 'rule'`

- [ ] **Step 3: Implement** — add the field + `_classify_rule` + set `rule=` on each return, per the mapping.

- [ ] **Step 4: Run tests**

Run: `ww-test backend --project suspicious score_process`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/engine.py Suspicious/Suspicious/score_process/tests/test_explanation_weighted_rule.py
git commit -m "feat(explanation): name the decisive rule on the weighted engine"
```

---

## Task 5: The adapters

**Files:**
- Create: `Suspicious/Suspicious/score_process/scoring/explanation/adapters.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_explanation_adapters.py`

**Interfaces:**
- Consumes: `VerdictExplanation`/`SourceLine` (Task 1), `compose` (Task 2), `ObservableVerdict`/`GroupVerdict` (Task 3), `CaseVerdict` (Task 4), `score_process.scoring.sources.source_verdict_from_report`
- Produces:
  - `explain_observable_group(case, group_verdict, per_observable, reports) -> VerdictExplanation`
    - `per_observable`: `list[ObservableVerdict]` (the case's per-observable verdicts, post-escalation)
    - `reports`: `list[AnalyzerReport]` for the case (any road-appropriate queryset)
  - `explain_mail_case(case, verdict, analyzer_reports, embedded_verdicts) -> VerdictExplanation`
    - `verdict`: `CaseVerdict`; `embedded_verdicts`: `list[ObservableVerdict]` from the embedded observables (may be `[]`)

**Behaviour:**
1. `rule` = `group_verdict.rule` (group case) or the escalated per-observable rule for a single-observable case; for mail, `verdict.rule`.
2. `sources` = one `SourceLine` per `AnalyzerReport`: `name = report.analyzer.name`; `tier`/`verdict` from `source_verdict_from_report(report)`; `note` = `sv.evidence` truncated to ~60 chars; `counted` = the source's `(tier, verdict)` is what the decisive rule acted on (helper `_counted(rule, sv) -> bool` — a per-rule predicate; unknown rule → all `counted=False`). Sort `counted` first, then tier asc.
3. `facts`: `source` = first counted source's name; `n_context` = `len(sources) - n_counted`; `n_counted`/`n_total`; `data_type` from the case; `missing` from `inconclusive_reason` mapped to a phrase.
4. `compose(rule, band, confidence, sources, **facts)` → the three text fields.
5. Return `VerdictExplanation(band, confidence, rule, analyst, reporter, reading, tuple(sources))`.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_explanation_adapters.py
from django.test import TestCase
from score_process.scoring.explanation.adapters import explain_observable_group, explain_mail_case
from score_process.scoring.observable_engine import ObservableVerdict, GroupVerdict
from score_process.scoring.engine import CaseVerdict
# build AnalyzerReport rows the way score_process/tests/test_screenshots_registry.py does
# (Analyzer needs analyzer_cortex_id, not `version`)


class AdapterTest(TestCase):
    def test_observable_group_basic(self):
        # a Dangerous group case, one GTI tier-1 malicious report
        ve = explain_observable_group(case, GroupVerdict("Dangerous", 90, {...}, ["..."], rule="group-worst-of"),
                                      [ObservableVerdict("Dangerous", 90, None, {...}, ["..."],
                                                         rule="tier1-authoritative-malicious")],
                                      reports=[gti_report])
        self.assertEqual(ve.band, "Dangerous")
        self.assertEqual(ve.decisive_rule, "group-worst-of")
        self.assertTrue(ve.analyst_paragraph)
        self.assertTrue(ve.reporter_paragraph)
        names = [s.name for s in ve.sources]
        self.assertIn("GTI", names[0] if names else "")

    def test_mail_escalation_rule_flows(self):
        ve = explain_mail_case(case, CaseVerdict(7, 80, "Dangerous", 1, 3, rule="embedded-ioc-escalation"),
                               analyzer_reports=[...], embedded_verdicts=[...])
        self.assertEqual(ve.decisive_rule, "embedded-ioc-escalation")
```

- [ ] **Step 2: Run to verify it fails** — `ModuleNotFoundError`

- [ ] **Step 3: Implement** per the behaviour spec.

- [ ] **Step 4: Run tests**

Run: `ww-test backend --project suspicious score_process.tests.test_explanation_adapters`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/explanation/adapters.py Suspicious/Suspicious/score_process/tests/test_explanation_adapters.py
git commit -m "feat(explanation): per-engine adapters to VerdictExplanation"
```

---

## Task 6: `Case.verdict_explanation` field + migration

**Files:**
- Modify: `Suspicious/Suspicious/case_handler/models.py` — after `verdict_rationale` (~line 104)
- Create: `Suspicious/Suspicious/case_handler/migrations/00NN_case_verdict_explanation.py` (via `makemigrations` — head is `0027_case_observable_group`, so this is `0028`)
- Test: `Suspicious/Suspicious/case_handler/tests/test_case_verdict_explanation_field.py`

**Interfaces:**
- Produces: `Case.verdict_explanation = models.JSONField(null=True, blank=True, default=None)`

- [ ] **Step 1: Write the failing test**

```python
# case_handler/tests/test_case_verdict_explanation_field.py
from django.test import TestCase
from case_handler.models import Case


class VerdictExplanationFieldTest(TestCase):
    def test_defaults_none(self):
        c = Case.objects.create()
        c.refresh_from_db()
        self.assertIsNone(c.verdict_explanation)

    def test_stores_dict(self):
        c = Case.objects.create(verdict_explanation={"band": "Safe", "sources": []})
        c.refresh_from_db()
        self.assertEqual(c.verdict_explanation["band"], "Safe")
```

> If `Case.objects.create()` needs required args, mirror an existing `case_handler/tests/` fixture.

- [ ] **Step 2: Run to verify it fails** — `FieldDoesNotExist`

- [ ] **Step 3: Add the field**

```python
# case_handler/models.py — after verdict_rationale
    # Structured explanation of the verdict (score_process.scoring.explanation).
    # None = not computed / old case; every render surface falls back to
    # verdict_rationale / _RESULT_GUIDANCE when null.
    verdict_explanation = models.JSONField(null=True, blank=True, default=None)
```

- [ ] **Step 4: makemigrations + test**

Run: `python manage.py makemigrations case_handler` (from `Suspicious/Suspicious/`), then `ww-test backend --project suspicious case_handler.tests.test_case_verdict_explanation_field`
Expected: migration `0028_case_verdict_explanation.py`; tests PASS

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/case_handler/models.py Suspicious/Suspicious/case_handler/migrations/0028_case_verdict_explanation.py Suspicious/Suspicious/case_handler/tests/test_case_verdict_explanation_field.py
git commit -m "feat(case): Case.verdict_explanation field"
```

---

## Task 7: Wire into finalization (both roads)

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/apply.py` — `finalise_ioc_group` builds + stores; `apply_verdict` gains `explanation=None`
- Modify: `Suspicious/Suspicious/score_process/scoring/cortex_analyzers/reports.py` — the mail scoring block builds the explanation and passes it to `apply_verdict`
- Test: `Suspicious/Suspicious/score_process/tests/test_explanation_finalization.py`

**Interfaces:**
- Consumes: `explain_observable_group`, `explain_mail_case` (Task 5); `Case.verdict_explanation` (Task 6)

**Behaviour:**
- `finalise_ioc_group`: after `g = score_group(...)`, inside a `try/except Exception` (log + continue), call `explain_observable_group(case, g, obs_verdicts, reports_for_case_iocs(case))` and set `case.verdict_explanation = ve.to_dict()`; add `"verdict_explanation"` to that function's final `case.save(update_fields=[...])`.
- `apply_verdict(case, verdict, explanation=None)`: if `explanation is not None`, `case.verdict_explanation = explanation` and add to `update_fields`.
- `reports.py` mail block (around `verdict = score_case(...)` → `apply_verdict(case, verdict)`): after the verdict + escalation are final, `try/except`: `ve = explain_mail_case(case, verdict, <the case's analyzer reports>, <embedded observable verdicts if available>)`; `apply_verdict(case, verdict, explanation=ve.to_dict())`.
- The reports queryset for each road: reuse whatever that road already has in scope (IOC: `per_obs` sources cover it, but the adapter wants `AnalyzerReport` rows — pass the reports from `collect_observable_sources` or a `reports_for_case`-style query; mail: the reports already loaded for scoring).

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_explanation_finalization.py
from django.test import TestCase
# build an IOC-group case with one malicious report, run finalise_ioc_group, assert
# case.verdict_explanation is a dict with band/decisive_rule/analyst_paragraph.
# build a mail case, run the mail scoring path (mirror test_screenshots_save_report.py's
# approach to reaching create_and_save_report), assert verdict_explanation populated.
# + a test: explain_* raising (patch it) -> case still finalizes, verdict_explanation None.
```

- [ ] **Step 2: Run to verify it fails**

- [ ] **Step 3: Implement** per the behaviour spec.

- [ ] **Step 4: Run tests**

Run: `ww-test backend --project suspicious score_process`
Expected: PASS (full suite — finalization is load-bearing)

- [ ] **Step 5: backtest**

Run: `ww-stack backtest --project suspicious` (or `python manage.py backtest_scoring` in the backend container)
Expected: verdict bands unchanged — explanation changes no score.

- [ ] **Step 6: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/apply.py Suspicious/Suspicious/score_process/scoring/cortex_analyzers/reports.py Suspicious/Suspicious/score_process/tests/test_explanation_finalization.py
git commit -m "feat(explanation): build + store VerdictExplanation at finalization"
```

---

## Task 8: `backfill_verdict_explanation` command

**Files:**
- Create: `Suspicious/Suspicious/score_process/management/commands/backfill_verdict_explanation.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_backfill_verdict_explanation.py`

**Interfaces:**
- Consumes: the adapters (Task 5)
- Produces: `python manage.py backfill_verdict_explanation [--dry-run] [--limit N]`

**Behaviour:** mirrors `score_process/management/commands/backfill_enrichment.py`. Iterate `Case` with `verdict_explanation__isnull=True` and a terminal `results` (not Inconclusive-because-ongoing). For each, rebuild the engine verdict from stored state is not possible cheaply — instead reconstruct a minimal `VerdictExplanation` from `case.results` + `case.final_confidence` + `case.verdict_rationale` + the case's `AnalyzerReport`s, using `rule="unknown"` (generic template) when the decisive rule can't be recovered. `--dry-run` writes nothing; `--limit`.

> Note for the implementer: recovering the exact `decisive_rule` for historical cases is out of scope — the backfill produces a best-effort generic explanation so old cases stop showing bare bullets. New cases (Task 7) get the real rule.

- [ ] **Step 1–5**: failing test (dry-run writes nothing; normal run populates; idempotent) → implement → tests green → commit `feat(explanation): backfill_verdict_explanation command`.

---

## Task 9: Expose `verdict_explanation` on the investigation API

**Files:**
- Modify: `Suspicious/Suspicious/api/serializers/investigations.py` — add `verdict_explanation` to the investigation **detail** payload (the `{"case": {...}}` dict around line 358, next to `final_score`), value = `obj.verdict_explanation` (the stored dict, or `None`)
- Test: `Suspicious/Suspicious/api/tests/test_investigation_verdict_explanation.py`

- [ ] **Step 1: failing test** — build a finalized IOC-group case with `verdict_explanation` set; `GET` the investigation detail (route `investigation-details`); assert `resp.data["case"]["verdict_explanation"]["decisive_rule"]` present; and `None` on a case without one. Not on the list serializer.
- [ ] **Steps 2–5** → implement → `ww-test backend --project suspicious api.tests.test_investigation_verdict_explanation api.tests.test_investigation_group` → commit `feat(api): verdict_explanation on the investigation detail`.

---

## Task 10: "Why this verdict" block in the HTML report

**Files:**
- Modify: `Suspicious/Suspicious/api/views/case_report.py` — pass `case.verdict_explanation` into the template context (it already passes `case`)
- Modify: `Suspicious/Suspicious/templates/case_report/report.html` — replace the bare `{% if case.verdict_rationale %}<ul>…` block (around line 83) with: if `case.verdict_explanation` → a "Why this verdict" section (`analyst_paragraph`, `confidence_reading`, a `sources` table: name · tier · verdict · counted · note); else keep the existing `verdict_rationale` `<ul>` fallback
- Test: `Suspicious/Suspicious/api/tests/test_case_report_verdict_explanation.py`

- [ ] **Step 1: failing test** — a case with `verdict_explanation` → report body contains the `analyst_paragraph` text and a source row; a case with only `verdict_rationale` → still renders the bullets.
- [ ] **Steps 2–5** → implement → `ww-test backend --project suspicious api.tests.test_case_report_verdict_explanation api.tests.test_case_report` → commit `feat(report): "Why this verdict" section from verdict_explanation`.

---

## Task 11: Reporter email uses `reporter_paragraph`

**Files:**
- Modify: `Suspicious/Suspicious/score_process/score_utils/send_mail/final_service.py` — in `_build_context` (the dict with `result_guidance`, ~line 195), add `"result_guidance": case.verdict_explanation["reporter_paragraph"] if case.verdict_explanation else _RESULT_GUIDANCE.get(raw_result, "...")`
- Modify: `Suspicious/Suspicious/score_process/score_utils/send_mail/modification_service.py` — same change to its `_build_context`
- (templates already render `{{ case.result_guidance }}` — no template change needed unless the wording label changes)
- Test: `Suspicious/Suspicious/score_process/tests/test_final_email_verdict_explanation.py`

- [ ] **Step 1: failing test** — build the `final_service` context for a case with `verdict_explanation` → `context["case"]["result_guidance"]` equals `reporter_paragraph`; without one → equals `_RESULT_GUIDANCE[band]`. Same for `modification_service`.
- [ ] **Steps 2–5** → implement → `ww-test backend --project suspicious score_process.tests.test_final_email_verdict_explanation` + the existing send-mail tests → commit `feat(email): reporter paragraph from verdict_explanation, guidance fallback`.

---

## Task 12: Frontend `VerdictExplanation` component

**Files:**
- Create: `suspicious-ui/src/features/investigation/VerdictExplanation.tsx`
- Create: `suspicious-ui/src/features/investigation/__tests__/VerdictExplanation.test.tsx`
- Modify: `suspicious-ui/src/features/investigation/api.ts` — add `verdict_explanation?: VerdictExplanationDTO | null` to the `InvestigationDetails` case type + the `VerdictExplanationDTO` interface (`band, confidence, decisive_rule, analyst_paragraph, reporter_paragraph, confidence_reading, sources: {name,tier,verdict,counted,note}[]`)
- Modify: the investigation page/layout component that renders the verdict/score (grep `final_score` / `classification` under `suspicious-ui/src`) — render `<VerdictExplanation data={details.verdict_explanation ?? null} />` near the verdict, shown only when non-null

**Component:** `analyst_paragraph` + `confidence_reading` always visible; a "Show source breakdown" toggle reveals the `sources` table (MUI `<Table>`). Null → renders nothing.

- [ ] **Step 1: failing test** (Vitest) — renders the paragraph + confidence reading; the table is hidden until the toggle is clicked; `data={null}` renders nothing.
- [ ] **Steps 2–5** → implement → `ww-test frontend --project suspicious` + `pnpm --dir suspicious-ui lint` + `pnpm --dir suspicious-ui build` → commit `feat(ui): VerdictExplanation panel on the investigation page`.

---

## Task 13: Whole-feature verification

- [ ] **Step 1:** `ww-test backend --project suspicious cortex_job score_process case_handler api` — all green
- [ ] **Step 2:** `ww-stack backtest --project suspicious` — **zero verdict-band drift** (the regression guard: this feature changes no score)
- [ ] **Step 3:** `ww-test frontend --project suspicious` + `pnpm --dir suspicious-ui lint` + `pnpm --dir suspicious-ui build`
- [ ] **Step 4:** remove any stray `Suspicious/Suspicious/gunicorn.conf.py`
- [ ] **Step 5:** update `docs/specs/2026-09-10-verdict-explanation-design.md` "What remains" if anything shifted; commit `docs: verdict explanation — verification run`

---

## Self-Review

**Spec coverage:**
- §1 contract → Task 1
- §2 rule enum → Tasks 3, 4 (+ listed at plan top)
- §3 engine changes → Tasks 3, 4
- §4 adapters → Task 5
- §5 composer → Task 2
- §6 storage + finalization + backfill → Tasks 6, 7, 8
- §7 renderers (API / report / email / frontend) → Tasks 9, 10, 11, 12
- Error handling table → Tasks 2 (unknown rule), 7 (adapter raises), 10/11 (null fallback)
- Testing table → each task's tests + Task 13

**Placeholder scan:** Task 3/4/5/8–12 test blocks describe fixtures rather than spelling every line — deliberate: the exact `Signal` / `AnalyzerReport` / `Case` construction differs by app version and the existing test modules (`test_screenshots_*`, `test_*engine*`, `test_investigation_group`) are the templates named in each task. Every *implementation* step has concrete code or an exact behaviour spec. No "add error handling" / "TBD".

**Type consistency:** `VerdictExplanation(band, confidence, decisive_rule, analyst_paragraph, reporter_paragraph, confidence_reading, sources)` and `SourceLine(name, tier, verdict, counted, note)` identical across Tasks 1, 5, 9, 10, 12. `compose(rule, band, confidence, sources, **facts) -> (analyst, reporter, reading)` matches Tasks 2 and 5. `ObservableVerdict.rule` / `GroupVerdict.rule` / `CaseVerdict.rule` added in Tasks 3–4, consumed in Task 5. `Case.verdict_explanation` (dict or None) — Tasks 6, 7, 9, 10, 11, 12. `explain_observable_group` / `explain_mail_case` signatures fixed in Task 5, called in Task 7.

**Open confirmations for the implementer (not blockers):**
- The exact mail finalization call site in `reports.py` (near `score_case` → `apply_verdict`) and whether the embedded-observable verdicts are in scope there — Task 7 note.
- The precise `score_observable` branch → `rule` mapping — Task 3 says read the function first.
- Whether `verdict_rationale` is currently on any investigation serializer (it is not — Task 9 adds `verdict_explanation` fresh, next to `final_score`).
