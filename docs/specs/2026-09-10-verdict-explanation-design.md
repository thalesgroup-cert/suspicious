# Verdict explanation — a legible "why" for every case

**Date:** 2026-09-10
**Status:** design, approved for planning
**Context:** SOC roadmap Lot 1/2 — *"Expliquer clairement les raisons du verdict / Réduire
les effets de boîte noire"*. Every P1 complaint from the SOC teams converged on the same
thing: the verdict appears without a reason. Today the "why" exists only as terse bullet
strings (`Case.verdict_rationale`, e.g. *"Trust-weighted malicious share is 67%."*), the
reporter-email "guidance" is a single static sentence per band (`_RESULT_GUIDANCE`), and the
`final_score` / `final_confidence` calculation is surfaced nowhere. The SOC also called out
the confidence pair specifically: *"score de risque très bas & score de confiance très bas =
pas sûr que pas de risque?"*
**Depends on:** the categorical verdict engine and `Case.verdict_rationale` (branch
`feat/ioc-analysis-road-and-verdict-model` / PR #326).

## Goal

At case finalization, build one structured `VerdictExplanation` object from whichever
scoring engine ran, store it on the `Case`, and render it in three places:

- **Investigation UI** and **downloadable HTML report** — the analyst view: a short
  explanatory paragraph, a plain-language reading of the (score, confidence) pair, and a
  medium-depth per-source breakdown.
- **Reporter notification email** — the reporter view: a plain-language paragraph of what
  the verdict means for them plus one recommendation line, no score internals.

Rule-based composition only — no generated text, no new dependency. The explanation is
**read-only over the existing verdict**: it changes no band, score, or confidence.

## Non-goals

- **No LLM / generated narrative.** A written contextualization + tailored recommendations
  ("analyse rédigée", SOC roadmap P4) is a separate project needing an LLM path.
- **No scoring-engine harmonization.** The IOC road keeps the categorical
  `observable_engine`; the mail road keeps `score_case`'s weighted logic. This spec defines
  the shared *output* contract (the `decisive_rule` key + `SourceLine` shape) that both
  engines feed — which is the groundwork a later harmonization needs, not the harmonization.
- **No i18n.** English, matching the rest of the codebase (`USE_I18N=True` but zero
  `gettext` usage anywhere).
- **No change to any band, score, or confidence**, and no new verdict inputs.
- The reporter recommendation is one rule-based sentence per band, not a tailored action
  plan.

## Design

### Data flow

```
finalise_ioc_group / mail finalization
  → adapters.explain_observable_group(...) | explain_mail_case(...)
      ← engine result (ObservableVerdict / GroupVerdict / score_case result), each now
        carrying a `rule` key
      ← the case's AnalyzerReports (for the SourceLine breakdown)
  → compose(rule, band, confidence, sources, **facts)
      → (analyst_paragraph, reporter_paragraph, confidence_reading)
  → VerdictExplanation  →  Case.verdict_explanation (JSONField)
  → API serializer (analyst view) · HTML report section · reporter email (reporter view)
```

### 1. The contract — `score_process/scoring/explanation/types.py`

```python
@dataclass(frozen=True)
class SourceLine:
    name: str        # analyzer display name
    tier: int        # 1 authoritative / 2 strong / 3 contextual / 0 untiered
    verdict: str     # "malicious" | "suspicious" | "clean" | "no-data" | "failed"
    counted: bool    # did this source feed the decisive rule?
    note: str        # short evidence, e.g. "trojan.mirai" / "no listing" / ""

@dataclass(frozen=True)
class VerdictExplanation:
    band: str                  # Safe | Suspicious | Dangerous | Inconclusive
    confidence: int            # 0-100
    decisive_rule: str         # closed enum (see §2)
    analyst_paragraph: str     # 2-4 sentences: the decisive rule + confidence reading
    reporter_paragraph: str    # 2-3 plain sentences + one recommendation line
    confidence_reading: str    # the plain (score, confidence) statement
    sources: list[SourceLine]  # per-analyzer breakdown, decisive sources first
```

Stored via `dataclasses.asdict`; read back as plain dicts by the renderers.

### 2. `decisive_rule` — the closed enum

Shared where the concept is shared; each engine maps its existing branch logic onto a key.

**Categorical engine (`observable_engine.score_observable`)** — the branches already append a
matching rationale string; they gain a `rule` label:

| rule | branch / meaning |
|---|---|
| `tier1-authoritative-malicious` | a Tier-1 source (GTI/VT/MISP) reports malicious → Dangerous |
| `tier2-consensus-malicious` | ≥2 Tier-2 sources agree malicious → Dangerous |
| `weighted-malicious-share` | trust-weighted malicious share over threshold → Dangerous |
| `tier1-authoritative-clean` | a Tier-1 source reports clean, nothing contradicts → Safe |
| `trusted-flag-not-decisive` | a trusted source flags it, evidence not decisive → Suspicious |
| `contextual-only-flag` | only Tier-3/contextual sources flag it → capped at Suspicious |
| `no-flag` | no source flags the indicator → Safe |
| `thin-coverage` | too few / too weak sources to assess → Inconclusive |
| `group-worst-of` | (group) verdict = worst band across the group's observables |

**Weighted engine (`score_case`)** — a small classifier maps its outcome:

| rule | meaning |
|---|---|
| `weighted-consensus` | the trust-weighted mean drove the band |
| `single-strong-signal` | one analyzer at ≥50 confidence drove it (the `max(worst_conf, …)` arm) |
| `embedded-ioc-escalation` | `mail_band_escalation` raised the band because an embedded observable did |
| `ai-classifier-decisive` | the AI phishing classifier was the decisive signal |
| `no-signal` | nothing flagged → Safe |
| `analysis-incomplete` | not enough completed analysis → Inconclusive |

Adding a rule key is additive; an unknown key falls back to a generic template (§4).

### 3. Engine changes (minimal)

- `ObservableVerdict` and `GroupVerdict` (`observable_engine.py`) gain `rule: str`. Each
  existing `return ObservableVerdict(...)` / `return GroupVerdict(...)` passes its key —
  ~9 one-word additions, no logic change.
- `score_case`'s result object gains `rule: str`, set by a new
  `_classify_rule(result, escalation, analyzer_results) -> str` helper that reads the
  already-computed band/score/escalation state. No change to how the band is decided.
- Both changes are covered by the existing engine tests plus one assertion each that the
  right key comes out for a known input.

### 4. Adapters — `score_process/scoring/explanation/adapters.py`

```python
def explain_observable_group(case, group_verdict, per_observable, reports_by_key) -> VerdictExplanation
def explain_mail_case(case, weighted_result, analyzer_reports, embedded_verdicts) -> VerdictExplanation
```

Each:
1. takes the engine result's `rule`, `band`, `confidence`;
2. builds `sources: list[SourceLine]` from the case's `AnalyzerReport`s — `tier` / `verdict`
   via the existing `source_verdict_from_report`; `note` from the report's category/evidence;
   `counted` = the source is of the tier/verdict the decisive rule acted on
   (e.g. for `tier1-authoritative-malicious`, the Tier-1 malicious sources are `counted`,
   the rest are context); decisive sources sorted first;
3. calls `compose(...)` for the three text fields;
4. returns the `VerdictExplanation`.

`explain_mail_case` merges the intrinsic analyzer sources (AI / YARA / sandbox / header /
FileInfo) with the embedded-observable verdicts into one `sources` list.

### 5. Composer — `score_process/scoring/explanation/compose.py`

- `_RULE_TEMPLATES: dict[str, {"analyst": str, "reporter": str}]` — parameterised
  sentences. Example (`tier1-authoritative-malicious`):
  - analyst: *"{source} is an authoritative threat-intelligence source and reported this
    {data_type} malicious — that determines the verdict on its own. {n_context} other
    source(s) were consulted for context."*
  - reporter: *"This was confirmed malicious by a trusted threat-intelligence source.
    {recommendation}"*
- `_CONFIDENCE_READINGS` — bucket `confidence` into `limited` (<40) / `moderate` (40-70) /
  `strong` (>70), one sentence each. **Special case:** `band == "Safe" and confidence < 40`
  → *"A low risk score with low confidence does not mean the item is safe — it means the
  analyzers could not gather enough signal to be sure. Treat it as unconfirmed."*
- `_RECOMMENDATION: dict[band, str]` — one sentence per band (Dangerous / Suspicious / Safe
  / Inconclusive), reused in the reporter paragraph.
- `compose(rule, band, confidence, sources, **facts) -> tuple[str, str, str]` returns
  `(analyst_paragraph, reporter_paragraph, confidence_reading)`. The analyst paragraph is
  the rule sentence + the confidence reading (+ for `thin-coverage` / `analysis-incomplete`,
  a "what's missing" clause). Unknown `rule` → a generic *"The verdict is {band} based on
  {n_counted} of {n_total} sources."* template so a new engine branch never crashes the
  composer.

### 6. Storage + finalization

- Migration: `case_handler` — `Case.verdict_explanation = models.JSONField(null=True,
  blank=True, default=None)`.
- `finalise_ioc_group` (IOC road) and the mail finalization path each call their adapter
  and assign `case.verdict_explanation` in the same `save()` that already writes
  `verdict_rationale` / `final_score`.
- Wrapped so an explanation failure logs and leaves `verdict_explanation` null — it must
  never block finalization (same discipline as the screenshot capture path).
- `score_process/management/commands/backfill_verdict_explanation.py` — mirrors
  `backfill_enrichment`: recompute for finalized cases with `verdict_explanation__isnull`,
  from the stored verdict + reports, `--dry-run` / `--limit`.

### 7. Renderers

- **API** — `verdict_explanation` (the full dict) added to the investigation-detail
  serializer, next to `verdict_rationale`. Not on the list serializer.
- **HTML report** (`templates/case_report/report.html`) — a "Why this verdict" block:
  `analyst_paragraph`, then `confidence_reading`, then a `sources` table (name · tier ·
  verdict · counted · note). Replaces the current bare `verdict_rationale` `<li>` list;
  keep the `<li>` list as the fallback when `verdict_explanation` is null.
- **Reporter email** (`final_email.jinja2`, `modification_email.jinja2`) — render
  `verdict_explanation.reporter_paragraph` where `_RESULT_GUIDANCE.get(band)` is used
  today. Keep `_RESULT_GUIDANCE` as the null fallback (pre-backfill cases, `Failure`,
  `AllowListed`, `Unchallenged`).
- **Frontend** — a `VerdictExplanation` component on the investigation page: the paragraph
  + `confidence_reading` always visible, the `sources` table behind a "show breakdown"
  toggle. Zod schema addition (`features/investigation/`), consumed on both roads.

### Error handling

| Failure | Behaviour |
|---|---|
| adapter / composer raises at finalization | logged; `verdict_explanation` stays null; finalization proceeds |
| `verdict_explanation` null at render time | report + UI fall back to `verdict_rationale` bullets; email falls back to `_RESULT_GUIDANCE` |
| unknown `decisive_rule` | generic template; never raises |
| an engine adds a branch without a rule key | `rule` defaults to a sentinel → generic template + a `logger.warning` |

## Testing

| Area | Tests |
|---|---|
| composer | iterate every rule key → non-empty analyst + reporter paragraph, no unfilled `{placeholder}`; unknown key → generic, no raise |
| confidence reading | each bucket; the `Safe` + `confidence < 40` special case produces the specific "does not mean safe" sentence |
| `explain_observable_group` | `ObservableVerdict` + reports → expected `rule`, `sources` (order, `counted` flags), band/confidence carried through |
| `explain_mail_case` | intrinsic + embedded sources merged; escalation → `embedded-ioc-escalation`; AI-decisive → `ai-classifier-decisive` |
| engine rule keys | `score_observable` returns the right key per branch; `_classify_rule` maps the weighted outcomes |
| finalization | `Case.verdict_explanation` populated on an IOC-group case and a mail case; adapter raising → case still finalizes, field null |
| `backtest_scoring` | zero verdict drift — explanation derives from the verdict, changes nothing |
| renderers | serializer field present / absent on list; report block renders + falls back; email uses `reporter_paragraph` + falls back; frontend component renders paragraph + toggled breakdown |
| `backfill_verdict_explanation` | `--dry-run` writes nothing; `--limit`; idempotent |

Every backend task ends with `python manage.py test cortex_job score_process api` green;
frontend tasks end with `pnpm test` green and `pnpm lint` clean.

## Rollout

Additive migration, no data migration. Existing cases show the current
`verdict_rationale` bullets until `backfill_verdict_explanation` runs. The feature is
self-gating: null `verdict_explanation` → every surface falls back to today's behaviour.

## What remains after this

- The LLM narrative + tailored recommendations (SOC roadmap P4) — a separate project.
- Full scoring-engine harmonization — the shared `rule` + `SourceLine` contract is the
  groundwork; the harmonization itself is its own spec.
