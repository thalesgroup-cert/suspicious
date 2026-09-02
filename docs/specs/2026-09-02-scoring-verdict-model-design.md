# Scoring & Verdict Model — Design

**Status:** Draft for review
**Date:** 2026-09-02
**Author:** Theo Bhang (Thales Group CERT)
**Related:** [`2026-09-02-ioc-analysis-road-design.md`](2026-09-02-ioc-analysis-road-design.md) · SOC roadmap feedback (Sept 2026) · GTI ↔ Suspicious verdict-gap analysis
**Council:** 2026-09-02 — the engine change must stay off the security-waiver critical path; any behaviour change is measured against a labelled regression set.

---

## 1. Problem

The SOC team compared Suspicious against Google Threat Intelligence on five indicators:

| Indicator | GTI | Suspicious | Gap | Root cause |
|---|---|---|---|---|
| Linux ELF Mirai — UPX packed | suspicious | suspicious | ✓ aligned | YARA rule on the packer + signature. |
| Linux ELF Mirai — unpacked | suspicious | **not suspicious** | false negative | No AV/GTI signal with weight. `worst = max(score where conf ≥ 50)` — nothing flagged with enough confidence. |
| 6 URLs / domains | 6 suspicious | 3 suspicious / 2 clean / 1 failed | under-detection | Thin URL enrichment; the failed analysis is silently counted as neutral and disappears from the UI. |
| `http://auth.users.pub` | not suspicious | **suspicious** | false positive | One noisy analyzer sets the band via "worst score"; no trusted source to counterweight. |
| `8.8.8.8` | not suspicious | **suspicious** | false positive | **No IP allow-list** (only file/filetype/domain/URL). Known infrastructure cannot be cleared. |

Two false negatives, two false positives, one aligned. The common thread: **per-analyzer confidence is miscalibrated and there is no hierarchy of trusted sources.**

Deeper, from reading the engine: the per-analyzer "score" is not a measurement. Every parser decides a categorical `level` (`safe` / `info` / `suspicious` / `malicious`) and then calls `get_level_score_confidence(level)` — a four-row lookup table (`malicious→10/100`, `suspicious→7/70`, `info→2/50`, `safe→0/100`). The engine then takes **weighted averages of those lookup-table numbers**, which is where opaque middles like `7.3/10` come from. The only analyzers with a real number are **VirusTotal** (an engine ratio, which the parser discards down to a level) and the **AI Mail Analyzer** (a genuine ML malscore).

So the 0–10 score is fake precision built on a category lookup. It is the "boîte noire" the SOC is objecting to, and it is the thing the author is "not fond of."

### Non-goals

- A formal per-signal explainability object on the engine (deferred, post-waiver, behind `backtest_scoring`).
- Per-team / per-tenant scoring policies.
- Retraining or re-weighting the AI Mail Analyzer model.
- Changing analyzer parsers' categorical output (they already produce the right thing — a `level`).

---

## 2. Principle

**Suspicious aggregates categorical source verdicts into one categorical case verdict, with a confidence and a plain-language rationale. It does not compute a risk number that analysts see.**

- A source (= one Cortex analyzer) returns a **categorical verdict**: `malicious` / `suspicious` / `clean` / `no-data`. Plus a **real confidence only when it has one** (VT engine ratio, AI malscore); otherwise the source's weight in the vote comes from its **trust tier**, not from a fabricated per-report confidence.
- `Analyzer.tier` (fixed, 1–3) = how much we trust this source. `Analyzer.weight` (tunable, within a tier) = fine adjustment.
- The case verdict is a **trust-weighted vote** → `Safe` / `Suspicious` / `Dangerous` / `Inconclusive` + an aggregate confidence + the list of who said what.
- `no-data` and `failed` are first-class and visible. Never counted as `clean`.
- `Case.score` / `final_score` survive as a **derived band number** (Safe≈2 / Suspicious≈6 / Dangerous≈9) for dashboard sort, KPI history, and TheHive severity only. Never displayed.

### Two roads, two presentations

| | Mail road | IOC road |
|---|---|---|
| Verdict driver | **AI Mail Analyzer score** (real ML) + YARA + sandbox | trust-weighted categorical vote of CTI sources |
| Shown as | a **score** (`malscore 3.1 · confidence 78% → Safe`) + three named components | a **ratio** (`3 / 9 trusted sources flagged this → Dangerous`) + per-source table |
| Engine change | **legibility pass only** — no aggregation change, `backtest_scoring` byte-identical | **new categorical engine** — greenfield, no regression surface |

The mail road keeps a real score because there is a real model behind it. The IOC road never had a defensible score, so it does not get one.

---

## 3. Mail-road verdict

The mail verdict is **three named components**, presented separately, not blended into one number:

```
Verdict: SUSPICIOUS
├─ Allow / Deny lists      hard override, checked first
│    deny hit → Dangerous · allow hit → AllowListed
├─ AI Mail Analyzer        primary score — malscore 3.1 · confidence 78% → Safe
│    (+ YARA, + sandbox as supporting signals on the score)
└─ Embedded IOCs report    escalation only — 1 of 4 flagged → Suspicious
     hxxp://bad.link   🔴 dangerous (GTI, MISP)
     evil@x.com        🟢 clean
     ...

→ Suspicious: an embedded IOC (GTI-confirmed) escalates the band over AI "Safe".
```

### Rules

1. **Deny/allow list** (existing `_compute_deny_listed` / `check_allow_list`): deny hit on any mail artifact → `Dangerous`, done. Full allow-list → `AllowListed`, done.
2. **Base verdict = AI Mail Analyzer**, combined with YARA and sandbox as supporting signals **on the score** (these three are the only inputs to `Case.score` and the base band). `score_ai` / `confidence_ai` stay the AI analyzer's own raw output. This is essentially today's AI-vs-signals blend, kept.
3. **Embedded IOCs escalate the band, never the score, never downward.** Each embedded URL/IP/hash/domain gets a categorical verdict from the IOC engine (§4). If the worst embedded-IOC verdict is higher than the AI band, the case band is raised to it (`Safe → Suspicious` or `→ Dangerous`). The displayed score does not move; the rationale line records the escalation.
4. `INCONCLUSIVE` reasons are made explicit in the payload and UI: `low_confidence` vs `ai_missing` vs `neutral`. This answers the team's "risk bas + confiance basse = ?" question — it is `Inconclusive (low confidence)`, not `Safe`.

### Engine change

Option **B** from the design discussion:

- `collect_signals` still gathers the AI signal, mail-artifact signals, and deny/allow flags.
- `score_case` for the mail road: **unchanged aggregation** of `{AI, YARA, sandbox}` signals → `Case.score` and a base band. This keeps `backtest_scoring` byte-identical.
- **New:** after `score_case`, a `mail_band_escalation(case_verdict, embedded_ioc_verdicts)` step raises the band per rule 3. Pure function, its own tests.
- **New:** `CaseVerdict` gains `inconclusive_reason`, `n_failed`, and a `rationale: list[str]` of human-readable lines. Additive — does not change existing fields, so stored-verdict comparison in `backtest_scoring` still holds.

`# ponytail: the mail engine's aggregation is not touched. Only a post-step (band escalation) and additive verdict metadata.`

---

## 4. IOC-road verdict (new categorical engine)

A new pure function, `score_observable(source_verdicts, tiers) -> ObservableVerdict`, and `score_group(observable_verdicts) -> GroupVerdict`. Lives beside `engine.py`, does not import or call `score_case`.

### 4.1 Source verdict

Each `AnalyzerReport` for the observable maps to:

```
SourceVerdict
  name         "GTI" | "VirusTotal" | "MISP" | "AbuseIPDB" | ...
  tier         1 | 2 | 3            # from Analyzer.tier
  weight       float                # from Analyzer.weight
  verdict      "malicious" | "suspicious" | "clean" | "no-data"
  confidence   int | None           # real number only for VT ratio / AI malscore
  evidence     str                  # "C2 infrastructure", "45/72 engines", "event #4821"
  raw          dict                 # report_full, for the detail view / full report
```

- The analyzer's existing categorical `level` maps directly: `malicious→malicious`, `suspicious→suspicious`, `safe→clean`, `info`/empty/`ongoing`→`no-data`.
- `status == "Failure"` → `verdict = "no-data"`, flagged as a failure (distinct from a clean "no-data").
- `no-data` sources are shown but do not vote.

### 4.2 Band logic — four legible rules

Given the voting sources (tier 1–3, each `malicious`/`suspicious`/`clean`):

| Verdict | Rule |
|---|---|
| **Dangerous** | a Tier-1 source says `malicious` with confidence ≥ `HIGH_CONFIDENCE` (default 70), or with no numeric confidence (tier alone carries it) · **or** ≥ 2 Tier-2 sources say `malicious` · **or** trust-weighted `malicious` share ≥ `DANGEROUS_SHARE` (default 0.5) |
| **Suspicious** | a trusted (Tier-1/2) source says `suspicious` or `malicious` but not enough for Dangerous · **or** only Tier-3 sources flag it (`malicious`/`suspicious`) — Tier-3-only evidence **caps at Suspicious** |
| **Safe** | ≥ 1 Tier-1 source says `clean` **and** no trusted source flags it |
| **Inconclusive** | fewer than `MIN_TRUSTED_COVERAGE` (default 1) Tier-1/2 sources returned a verdict — regardless of the ratio |

Each rule that fires contributes a `rationale` line. Rule order: Inconclusive-coverage check first, then Dangerous, then Safe, then Suspicious as the fallback when something flagged it.

Trust-weighted share = `Σ(weight · tier_multiplier for sources voting malicious) / Σ(weight · tier_multiplier for all voting sources)`, with `tier_multiplier` default `{1: 4, 2: 2, 3: 1}`.

### 4.3 Confidence

```
confidence = base_from_agreement × coverage_factor × (1 − failure_penalty)
```

- `base_from_agreement`: how lopsided the weighted vote is (unanimous → high, split → low).
- `coverage_factor`: scales with how many Tier-1/2 sources returned data.
- `failure_penalty`: rises with failed sources, weighted by tier — a failed Tier-1 hurts confidence a lot.

Low confidence does **not** flip the verdict, but a verdict below `MIN_TRUSTED_COVERAGE` is reported as `Inconclusive`.

### 4.4 Group verdict

`score_group` = worst-of the per-observable bands, plus counts. Band ordering: `Dangerous > Suspicious > Safe`. `Inconclusive` observables are **ignored for banding** — the group band is the worst band among observables that reached a verdict; the group is `Inconclusive` **only** when *every* observable is `Inconclusive`.

```
GroupVerdict
  band          worst band among non-inconclusive observables; Inconclusive iff all are
  confidence    min confidence among observables at the worst band
  counts        {dangerous: 2, suspicious: 3, clean: 6, inconclusive: 1}
  rationale     ["2 of 12 observables are Dangerous", "1 could not be assessed", ...]
```

The group's derived `Case.score` = band → number (for KPI/dashboard/TheHive only).

---

## 5. `Analyzer` model changes

```
Analyzer.tier   PositiveSmallIntegerField(choices=[(1,"Authoritative"),(2,"Strong"),(3,"Contextual")], default=3, db_index=True)
```

- `weight` stays (default 0.2), now explicitly "fine adjustment within tier".
- Seeded per known analyzer in a data migration:

| Tier | Analyzers |
|---|---|
| 1 — Authoritative | GTI (when integrated), VirusTotal (with a real detection count), internal deny/allow lists, MISP (matched event) |
| 2 — Strong | AI Mail Analyzer, ThreatGrid / sandbox, YARA (boosted), CIRCL Hashlookup |
| 3 — Contextual | AbuseIPDB, Shodan, urlscan, Zscaler, single-vendor reputation, heuristic analyzers |
| — no verdict | Shodan / FileInfo when used purely for enrichment → always `no-data`, never vote |

- Editable in the Settings UI alongside `weight` (`AnalyzerSettingsDetailView` — add `tier` to the serializer). **Fixed classification, rarely changed**; not per-run.

---

## 6. IP allow-list (Lot 1, independent, do first)

- New `AllowListIp` model (mirror `AllowListDomain`).
- `check_allow_list` gains an `ip` branch.
- Settings UI list section for it (`SettingsListView` handles list sections generically).
- Seed with a short list of well-known infrastructure (public DNS resolvers, major CDNs) — as data, not hardcoded.
- Fixes `8.8.8.8` and its whole class immediately, with no engine change.

---

## 7. Confidence-scale cleanup

Today confidence is `0–100` in `get_level_score_confidence`, `×10` after `compute_weighted_scores`, `÷10` back in `_signals_from`. One off-by-ten away from a silent bug.

- Normalise to **one 0–100 scale end to end**. Remove the `×10` in `compute_weighted_scores` and the `/10` in `_signals_from`; adjust `CONF_FLOOR` references.
- Covered by `backtest_scoring` — must stay byte-identical for mail + legacy-IOC cases (this is a representation change, not a behaviour change).
- `# ponytail: pure cleanup. If backtest drifts, the rescale had a latent bug — good to know before v2.`

---

## 8. Labelled regression harness

`backtest_scoring` today diffs new-engine output against each case's stored (old) verdict — a drift detector. For a **deliberate** behaviour change it is the wrong oracle.

- Add a `scoring/fixtures/labelled_cases/` set: the 5 GTI cases to start, each with `{observable, source_reports, expected_band}`. Grow it every time the SOC reports a wrong verdict.
- New `manage.py score_accuracy` command: run the engine over the labelled set, report accuracy / confusion matrix (`false positive`, `false negative`, aligned).
- CI gate: accuracy must not regress.
- `backtest_scoring` keeps its role for the **mail path** (no drift allowed) and gains a `--road` filter.

---

## 9. `INCONCLUSIVE` and the "boîte noire" UI

- `CaseVerdict.inconclusive_reason ∈ {low_confidence, ai_missing, neutral, thin_coverage}`.
- UI: the verdict badge carries the reason — `Inconclusive · low confidence`, not a bare `Inconclusive`.
- The rationale list renders as bullet points under the verdict on both roads. This *is* the "paragraphe explicatif" the SOC asked for — assembled from structured rules, no LLM needed for v1.
- `# ponytail: rationale is a list[str] built by the rules. An LLM-written narrative is a later, optional layer on top.`

---

## 10. Migration & rollout

| Step | Risk |
|---|---|
| `Analyzer.tier` field + seed migration | none (additive) |
| `AllowListIp` + `check_allow_list` branch + seed | low, isolated |
| Confidence-scale cleanup | low — `backtest_scoring` gates it |
| IOC-road categorical engine (`score_observable` / `score_group`) | **none on existing cases** — only the new IOC road calls it |
| Mail-road band-escalation post-step + verdict metadata | low — additive, `backtest_scoring` byte-identical on aggregation |
| Drop displayed score on IOC road (UI + serializer) | low — `Case.score` still written; KPI/dashboard already categorical |
| TheHive severity from `case.results` not score | low — one mapping function |

No `scoring.engine_v2` flag is needed: the mail engine is not being swapped, and the IOC engine is greenfield. If the mail band-escalation step proves risky, gate *that step* alone behind a setting.

---

## 11. Testing

| Area | Tests |
|---|---|
| `score_observable` | each of the 4 band rules in isolation; Tier-3-only caps at Suspicious; Tier-1 clean + Tier-3 noise → Safe; thin coverage → Inconclusive; failed Tier-1 → confidence drop; `no-data` sources don't vote. |
| `score_group` | worst-of banding; counts; all-inconclusive → Inconclusive. |
| Mail band escalation | AI Safe + embedded Dangerous URL → case Suspicious/Dangerous, score unchanged; escalation never lowers; rationale line present. |
| `inconclusive_reason` | each of the four reasons produced in the right situation. |
| `AllowListIp` | `8.8.8.8` in the list → clean; deny-list still wins over allow. |
| Confidence scale | `backtest_scoring` byte-identical across all existing cases after the rescale. |
| `score_accuracy` | the 5 GTI cases resolve to their labelled bands with the seeded tiers (GTI as Tier-1). |
| Regression | `backtest_scoring --road mail` — zero drift. |
| Serializer | IOC-road detail returns categorical verdict + per-source table + no score field; mail-road returns the AI score + three components. |
| TheHive | severity derived from `case.results` matches the old score→severity mapping for each band. |

---

## 12. Sequencing

1. **Live spike:** pull ~20 finalised cases' `report_full` from the running Cortex instance; confirm every analyzer type in use maps cleanly to one of `malicious`/`suspicious`/`clean`/`no-data` + whether it carries a real confidence. Adjust the tier seed list to what is actually deployed.
2. `Analyzer.tier` field + seed migration + Settings UI.
3. `AllowListIp` + `check_allow_list` branch + seed. *(Ships independently — closes the `8.8.8.8` gap in Lot 1.)*
4. Confidence-scale cleanup, gated by `backtest_scoring`.
5. `score_observable` / `score_group` + labelled harness + `score_accuracy`. Wire into the IOC road (sibling spec step 5).
6. Mail band-escalation post-step + `CaseVerdict` metadata + `inconclusive_reason`.
7. Drop displayed score on the IOC road; rationale bullets on both roads; TheHive severity remap.
8. GTI integration as a Tier-1 analyzer (Cortex config + contrib parser + tier seed) — closes the Mirai-unpacked and `auth.users.pub` gaps.

Steps 1–3 land in Lot 1 and need no engine change. Steps 5–8 land alongside the IOC-road page.
