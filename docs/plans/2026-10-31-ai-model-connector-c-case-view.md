# AI Model Connector, Plan C: Case View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the one-line "AI classifier" caption in the submission drawer and the investigation overview with an "AI model assessment" section, shown only while the `ai_model` connector is enabled.

**Architecture:** One backend presenter (`ai_model/presentation.py`) turns an `AiAssessment` plus the case into a plain dict (class, tier, runner-up, version, age, similar cases, campaign line, cross-check). Both detail serializers expose it as `ai_assessment` (`null` when the connector is off or the case has no assessment). One React component renders it in both places; when the field is `null` the legacy caption stays.

**Tech Stack:** Django REST serializers, React 19 + MUI v9 + TypeScript, Vitest browser mode, Playwright.

**Spec:** `docs/specs/2026-10-30-ai-model-connector-design.md` (sections 7 "Campaign cross-check", 8 "Case section", 9). Master plan: `docs/plans/2026-10-30-ai-model-connector.md`, Plan C.

## Global Constraints

- Backend paths are relative to `Suspicious/Suspicious/`, UI paths to `suspicious-ui/`. Backend tests: `ww test backend <label>`; UI: `pnpm test`, `pnpm lint`, `pnpm test:e2e` from `suspicious-ui/`.
- TDD for every behaviour change (failing test first, shown in the report).
- Conventional Commits (subject at most 72 characters, body lines at most 100), no `Co-Authored-By` trailer, explicit `git add <paths>`, nothing pushed, remove a stray root-owned `Suspicious/Suspicious/gunicorn.conf.py` before committing.
- No numeric confidence is shown to people (spec section 8). No mail content or free text from the AI server in logs.
- No new dependency, no i18n library (strings are English literals, as elsewhere in the UI).
- Docs prose: no em dashes, no filler vocabulary, every claim checked against the code.
- `CHANGELOG.md` entry under Added for the new section.

## Review Focus

- Connector disabled: `ai_assessment` is `null` in both serializers and the legacy caption shows (Task 2, 4).
- Version 0 has no tier (`AiAssessment.tier == ""`): the UI says "confidence not calibrated", never a made-up tier (Task 1, 3).
- A case with no `AiAssessment` row (analysed by the old Cortex job): `null`, legacy caption stays (Task 2).
- `similar_cases` naming a case the viewer may not open: that entry is dropped (Task 1).
- Case in a campaign: the line shows reference and size; no sibling labels yet because no label store exists before Plan D (Task 1).
- The detail endpoints add no query per case beyond the `select_related` (Task 2).

## Calls made in this plan

- **Ruling C1: null from the backend, no UI hook on `connectors/enabled`.** The master outline had the UI read the enabled-connectors endpoint. One source of truth is simpler: the serializer returns `null` when the connector is disabled, and the UI renders on `null`. Cost if wrong: a stale payload cached by the client shows until refetch.
- **Ruling C2: legacy caption stays when `ai_assessment` is `null`.** Spec section 8 hides stored sections when the module is off; it does not say the Cortex-era caption goes too. Keeping it leaves old cases informative. Cost if wrong: a one-line follow-up removes it.
- **Ruling C3: no tier in version 0.** The server returns `tier: None` for version 0 (`inference_server/v2.py:68`). The UI does not derive one; it shows "Confidence not calibrated" and the runner-up is skipped (it appears only on tier `low`).
- **Ruling C4: sibling labels, "campaign members disagree" and the review queue wait for Plan D.** No label field exists on `Case` or `CampaignMember` today. Plan C ships the campaign reference and size only.
- **Ruling C5: flagged links are not in the cross-check.** The verdict explanation has no flagged-link structure. The facts are: decisive rule, counted sources with their verdicts, and the allow/deny list hit from `Case.is_allowlisted`, `is_denylisted`, `list_reason`.
- **Ruling C6: the cross-check is built on the server.** The drawer API does not serialize `verdict_explanation` today; building the facts in `presentation.py` serves both views and keeps the explanation private to the case's viewers.

## Contracts

`ai_assessment` payload (or `null`):

```json
{
  "result": "Dangerous",
  "sub_class": "CREDENTIAL_PHISHING",
  "tier": "high" | "medium" | "low" | "",
  "runner_up": {"result": "Safe"} | null,
  "model_version": "v0",
  "analysed_at": "2026-10-31T10:00:00Z",
  "reads": "body only",
  "similar_cases": [{"case_id": 12, "similarity": 0.91, "label": "Dangerous", "provenance": "analyst"}],
  "campaign": {"ref": "261031-865a1", "size": 9} | null,
  "cross_check": {"facts": [{"kind": "rule" | "source" | "list", "text": "..."}], "disagrees": false}
}
```

---

### Task 1: Presenter and cross-check

**Files:**
- Create: `ai_model/presentation.py`, `ai_model/tests/test_presentation.py`
- Reuse: `ai_model/models.py` (`AiAssessment`), `case_handler/models.py` (`Case`, `Campaign`, `CampaignMember`), `api/permissions/submissions.py` (`submission_queryset`)

**Interfaces:**
- Produces: `present_assessment(case, user) -> dict | None`. Returns `None` when `case` has no `ai_assessment`. Reads `case.ai_assessment` and `case.campaign_membership` with `getattr(..., None)`.
- Produces: `cross_check(case, assessment) -> dict` with the `cross_check` shape above.

- [ ] **1. Tests first** (`test_presentation.py`, existing Case factories/fixtures from `ai_model/tests`): version 0 (`tier=""`) gives `tier == ""` and `runner_up is None`; tier `low` with `probabilities={"Dangerous": 0.48, "Safe": 0.42, "Unwanted": 0.10}` and result Dangerous gives `runner_up == {"result": "Safe"}`; `similar_cases` entry whose case the user may not open (`submission_queryset(Case.objects.all(), user)` excludes it) is dropped, the allowed one kept; a case in a campaign of 3 members gives `{"ref": ..., "size": 3}`, a case outside one gives `None`; no `AiAssessment` gives `None`.
- [ ] **2. Cross-check tests:** a case with `verdict_explanation={"decisive_rule": "deny-listed", "band": "Dangerous", "sources": [{"name": "VirusTotal", "verdict": "malicious", "counted": true}, {"name": "x", "verdict": "clean", "counted": false}]}`, `is_denylisted=True`, `list_reason="bad.example"` gives facts `rule`, one `source` (counted only), one `list`; AI Safe against band Dangerous gives `disagrees True`; AI Dangerous against band Safe gives `True`; same side gives `False`; `verdict_explanation=None` gives no rule or source facts and `disagrees False`.
- [ ] **3. Implement** `present_assessment` and `cross_check` in `presentation.py`. The `text` of each fact is one plain English sentence (for example "Decisive rule: deny-listed"). `disagrees` compares the AI class against the explanation `band` on the Safe/Dangerous axis only (Unwanted, Suspicious and Inconclusive never disagree). `analysed_at` is `assessment.updated_at`. `reads` is the constant `"body only"`.
- [ ] **4. Run** `ww test backend ai_model`. Commit: `feat(ai-model): present an assessment with its cross-check`.

### Task 2: Serializers and querysets

**Files:**
- Modify: `api/serializers/submissions.py` (`SubmissionDetailsSerializer`), `api/serializers/investigations.py` (`InvestigationDetailsSerializer`), `api/views/submissions.py` (`CASE_DETAIL_SELECT_RELATED` use in `SubmissionDetailsView.get_queryset`), `api/views/investigations.py` (`get_case_detail_queryset`), tests in `api/tests/`

**Interfaces:**
- Consumes: `present_assessment(case, user)` (Task 1), `connectors.registry`/`get_state` as `EnabledConnectorsView` uses them (`api/views/connectors.py:87`).
- Produces: `ai_assessment` key at the top level of both detail payloads.

- [ ] **1. Tests first:** connector enabled and assessment present gives the payload; connector disabled gives `None` even with an assessment; enabled without an assessment gives `None`; a query-count test on each detail endpoint (`assertNumQueries` compared with and without an assessment) shows no extra query per case.
- [ ] **2. Implement** a `SerializerMethodField` `ai_assessment` on both serializers: return `None` unless `get_state("ai_model").enabled`, else `present_assessment(obj, self.context["request"].user)`. Add `"ai_assessment"` and `"campaign_membership__campaign"` to the detail `select_related` of both views.
- [ ] **3. Run** `ww test backend api ai_model`. Commit: `feat(api): expose the AI assessment on case detail`.

### Task 3: Component

**Files:**
- Create: `src/features/submissions/components/AiAssessmentSection.tsx`, `src/features/submissions/__tests__/AiAssessmentSection.test.tsx`
- Modify: `src/features/submissions/api.ts` (type `AiAssessment` exported, field `ai_assessment?: AiAssessment | null` on `SubmissionDetails`), `src/features/investigation/api.ts` (same field on `InvestigationDetails`)

**Interfaces:**
- Produces: `AiAssessmentSection({ assessment }: { assessment: AiAssessment })`, plus the exported `AiAssessment` type matching the Contracts block.

- [ ] **1. Tests first** (Vitest browser, existing `__tests__` style): tier `high` shows "High" and its meaning text; tier `low` shows "Low" and "Runner-up: Safe"; tier `""` shows "Confidence not calibrated" and no tier chip; similar cases render a row each with label and provenance, none renders no table; campaign line shows "Campaign 261031-865a1, 9 mails"; `cross_check.disagrees` shows "AI disagrees with the evidence"; the text "body only" statement is present; no `%` or numeric confidence appears anywhere.
- [ ] **2. Implement** the component with MUI `Stack`, `Chip`, `Table`. Tier meanings: High "The model is confident", Medium "The model leans this way, check the evidence", Low "The model is unsure, rely on the other evidence".
- [ ] **3. Run** `pnpm lint` and `pnpm test`. Commit: `feat(ui): AI assessment section component`.

### Task 4: Wire into the drawer and the overview

**Files:**
- Modify: `src/features/submissions/components/OverviewTab.tsx` (caption block at lines 94-114), `src/features/investigation/components/InvestigationOverview.tsx` (`<Section title="AI classifier">` at lines 150-168), their existing tests

- [ ] **1. Tests first:** with `ai_assessment` set, the section renders and the legacy chips ("score", "conf", "cat") do not; with `null` or absent, the legacy caption renders as today. One test per component.
- [ ] **2. Implement** the conditional in both files (Ruling C2).
- [ ] **3. Run** `pnpm lint`, `pnpm test`. Commit: `feat(ui): show the AI assessment in the drawer and overview`.

### Task 5: End to end, docs, changelog

**Files:**
- Create: `e2e/ai-assessment.spec.ts`
- Modify: `CHANGELOG.md`, `docs/components/analyzers.md` (a short "Case view" paragraph), `docs/plans/2026-10-30-ai-model-connector.md` (mark Plan C done)

- [ ] **1. Playwright path:** open a submission drawer for a case with a mocked `ai_assessment` payload (route fulfil, as the existing specs do) and check the section's heading, the tier chip and the campaign line; a second case with `ai_assessment: null` shows the legacy caption.
- [ ] **2. Docs:** the paragraph states what the section shows, that it appears only with `ai_model` enabled, that version 0 has no tier, and that sibling labels arrive with the label ledger (Plan D). CHANGELOG Added bullet. Check each claim against the code.
- [ ] **3. Run** `pnpm test:e2e` for the new spec, then the full `ww test backend`. Commit: `docs(ai-model): case view section`.
