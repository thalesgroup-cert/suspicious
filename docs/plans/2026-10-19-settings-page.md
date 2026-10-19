# Settings Page Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the Settings console findable (grouped, deep-linkable sections, one header, a status strip), safe (confirmations, undo, honest bulk results, unsaved-changes guard, a weight-sum guard) and readable (analyzer scoring as a searchable table with shares, connector labels and delivery statuses, theme-safe colours, accessible controls).

**Architecture:** Frontend-only restructuring of `pages/SettingsPage.tsx` and `features/settings/*` around a route `settings/:section?`, a grouped nav, a status strip built from queries the page already runs, and three small shared pieces (`ConfirmDialog`, `runBatch`, an unsaved-changes registry). One additive backend check refuses a weight update that would make the total weight of active analyzers zero.

**Tech Stack:** React 19, MUI 9, React Router 7 (data router), TanStack Query 5, notistack, Vitest browser mode; Django/DRF (`api/views/settings.py`, `api/serializers`).

**Spec:** `docs/plans/2026-10-19-settings-page-design.md` (binding).

## Global Constraints

- Admin/CERT access unchanged (`IsAdminOrCERT`, `ProtectedRoute requireGroups={ADMIN}`); no new endpoints; no data model change; the only backend change is the weight-sum guard (additive, 400 on violation).
- Honest numbers and copy: the status strip shows only data the page fetches; the scoring share column is `weight / sum(weights of all analyzers listed)` and says so; no claim about a case's score beyond "a case's score is the weighted average of the analyzers that ran on it".
- Save model (Primer): explicit Save for text/grouped edits, instant save only for toggles (connector enable, feeder switch); never mix both in one form; keep user data when a save fails; keep Save enabled and say "Nothing to save" when clean; results that matter are shown inline (`role="status"`), snackbars are secondary.
- Destructive actions: single-entry removal is reversible (Undo re-adds the value through `addItems`); bulk delete, feeder off and discarding unsaved changes ask for confirmation stating the consequence and the count.
- Frontend: reuse `SoftCard`/`InnerCard`, `EmptyList`, `useResultColors`/`ensureContrast`/`readableOnTint`, theme typography (`pageTitle`, `subtitle2`, `caption`); no literal colours (`#22C55E`, `#F59E0B`, `#EF4444` go), no inline `fontWeight` above 700 or `letterSpacing`, no text below the theme caption size; text 4.5:1, marks 3:1 in every theme; no em dashes in UI copy.
- Accessibility: h1 page, h2 per panel, h3 sub-sections; unique region names; nav items `aria-current="page"`; sliders named and with `aria-valuetext`; dialogs trap and return focus; reduced motion respected; state never by colour alone.
- Conventional Commits, trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; nothing pushed; never stage `deployment/compose_apps.yaml`; no `git stash`.
- Gates: `npx vitest run`, `npx tsc -b`, `npx eslint .` (0 errors; 4 pre-existing warnings), e2e submit + ioc-road 7/7 (`e2e/investigation.spec.ts` keeps only main's 2 known failures); backend `ww test backend api dashboard` green. Host `node` is v18: `export PATH=$CLAUDE_JOB_DIR/tmp/bin:$PATH` (node 24); pnpm is not on PATH (use `npx`). Rebuild the Docker UI/`suspicious` images before live captures.

## Review Focus

1. Navigation by URL: unknown section redirects to the first, trailing slash, browser Back/Forward, deep link on first load, a non-Admin/CERT user still sees "Not authorized".
2. Bulk delete and Save all with one failing item: counts true, failed items stay selected/modified, list refreshed, no unhandled rejection.
3. Weights: all zero, sum zero, one analyzer at 0 (allowed), inactive analyzers (excluded from the sum, as in the guard), 0.1 float steps; the guard in UI and API.
4. Unsaved changes: leaving the section, route change, closing the tab, discard confirm, Save with nothing to save, a failed save keeps the draft.
5. Keyboard-only and screen-reader use of nav, slider + number input, table sort, confirm dialog focus return; phone width; all themes; reduced motion.

## File Structure

- Frontend modify: `src/pages/SettingsPage.tsx`, `src/app/router.tsx` (route `settings/:section?`), `src/features/settings/components/{sections.tsx,EditableListPanel.tsx,ReadOnlyListPanel.tsx,FeederPanel.tsx,CisoUsersPanel.tsx,ConnectorList.tsx,ConnectorDetail.tsx,ConnectorsPanel.tsx,configFieldHelpers.tsx,cards.tsx}`, `src/features/settings/api.ts`; replace `ScoringPanel.tsx` with `ScoringTable.tsx`.
- Frontend create: `features/settings/components/{SettingsNav.tsx,StatusStrip.tsx,ConfirmDialog.tsx}`, `features/settings/{batch.ts,unsaved.tsx,weights.ts,labels.ts}`; tests beside them (`__tests__/`) and extend `pages/__tests__/SettingsPage.test.tsx`; a11y test `pages/__tests__/SettingsPage.a11y.test.tsx`.
- Backend modify: `Suspicious/Suspicious/api/views/settings.py` (`AnalyzerSettingsDetailView.patch`), tests in `api/tests/test_analyzer_settings.py`; docs where the endpoint is described (grep `settings/analyzers`).

---

### Task 1: Foundation: route, grouped nav, header, status strip, shared safety pieces

**Interfaces (produces):**
- Route `settings/:section?` in `app/router.tsx`; `SectionKey` unchanged; `SECTIONS` gains `group: "lists"|"access"|"ingestion"|"scoring"|"integrations"` and a `GROUPS: {key,label,sections}[]` export (labels: Detection lists, Access, Ingestion, Scoring, Integrations); `parseSection(raw: string | undefined): SectionKey | null`.
- `SettingsNav` props `{ active: SectionKey; unsaved: ReadonlySet<SectionKey>; onNavigate(key) }` (desktop: sticky rail inside a `nav` landmark named "Settings sections", group labels are plain list-group labels, not headings, so the outline stays h1 > h2; items are links with `aria-current="page"`; phone: a labelled picker). Items show title only; unsaved items show a dot and the visually hidden text "unsaved changes".
- `StatusStrip` (no props): feeder (`getFeederStatus` + `FeederHealthBadge`), connectors (`listConnectors`: enabled of total, unhealthy count from `last_health_ok === false`), analyzers (`listAnalyzers`: active of total); each cell loads independently, failed cell says "unavailable", each links to its section.
- `ConfirmDialog` props `{ open, title, body: ReactNode, confirmLabel, destructive?: boolean, onConfirm(): void, onCancel(): void }`; MUI `Dialog` with `aria-labelledby`/`aria-describedby`, initial focus on Cancel for destructive, focus returns to the opener.
- `batch.ts`: `runBatch<T>(items: T[], op: (item: T) => Promise<unknown>): Promise<{ ok: T[]; failed: { item: T; error: unknown }[] }>`, sequential, never throws; `summarise(ok, failed, noun): string` -> "3 of 5 deleted, 2 failed".
- `unsaved.tsx`: `UnsavedProvider`, `useReportUnsaved(key: SectionKey, dirty: boolean)`, `useUnsavedKeys(): ReadonlySet<SectionKey>`; the provider installs a `beforeunload` handler while the set is non-empty and a React Router `useBlocker` that opens `ConfirmDialog` ("Discard unsaved changes?").

- [ ] **Step 1: Failing tests:** `parseSection` (valid, unknown, undefined, trailing slash); SettingsPage at `/settings/scoring` opens scoring, at `/settings/nope` redirects to `/settings/domains_allow`, at `/settings` opens the first; clicking a nav item changes the URL and Back restores; nav is grouped with the five labels, items carry `aria-current` only on the active one; non-Admin/CERT -> "Not authorized"; header has one h1 "Settings" and a subtitle naming lists, access, feeder, scoring and connectors, one Refresh button that invalidates settings, connectors, connector-config and connector-deliveries queries (spy on `invalidateQueries` predicate); the avatar and "Admin console" card are gone; StatusStrip renders the three facts from mocked queries, one failing query says "unavailable" while the others render; `runBatch` (all ok, middle fails, all fail, empty, never rejects, order preserved), `summarise`; `ConfirmDialog` (focus on Cancel when destructive, Esc cancels, confirm calls once, focus returns); `unsaved` (set updates, beforeunload prevented only when dirty, blocker prompts and discard proceeds, cancel stays).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the route, nav, header, strip, helpers; panel title in the content card becomes the panel's own `h2` with the section subtitle; remove `useState` for the active section; heading outline h1 > h2 (panel) > h3.
- [ ] **Step 4: Gates** (vitest, tsc, eslint) pasted.
- [ ] **Step 5: Commit** `feat(ui): settings sections by URL with grouped nav, status strip and shared safety helpers`.

### Task 2: Lists, feeder and CISO safety

**Interfaces (consumes):** `ConfirmDialog`, `runBatch`, `summarise`, `useReportUnsaved` (Task 1).

- [ ] **Step 1: Failing tests:** single entry removal: no dialog, entry removed, snackbar with an Undo action; Undo calls `addItems(section,[value])` once and refreshes; an Undo that fails says so and does not claim success; bulk delete asks "Delete N entries from <list>? This cannot be undone." (N = selected visible), Cancel does nothing, Confirm runs `runBatch`; with the 2nd of 3 failing: inline `role="status"` text "2 of 3 deleted, 1 failed", the failed id stays selected, the list is refreshed, no unhandled rejection (listen for `unhandledrejection`); feeder switch off opens the confirm with the consequence text, on does not; cancel leaves the switch on; feeder colours come from the palette (no literal hex in rendered styles), "Running"/"Stopped" text always shown; the Add button, when disabled, has a description "Enter at least one value" (`aria-describedby`); empty states use `EmptyList`; CISO panel headings are `h3` inside the panel `h2`; Watcher read-only panels keep working.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** in `EditableListPanel.tsx`, `FeederPanel.tsx`, `ReadOnlyListPanel.tsx`, `CisoUsersPanel.tsx`; replace `handleBulkDelete` loop with `runBatch`; remove `#22C55E`; keep list semantics unchanged.
- [ ] **Step 4: Gates; commit** `fix(ui): settings lists and feeder ask before destructive actions and report batches honestly`.

### Task 3: Analyzer scoring table and the weight-sum guard

**Interfaces (produces):** `weights.ts`: `shares(weights: {id:number; weight:number; is_active:boolean}[]): Map<number, number>` (weight / sum over all listed, 0 when the sum is 0, rounded display helper `formatShare`), `activeSum(weights): number`, `wouldZeroTotal(next): boolean` (true when the sum of ACTIVE analyzers' weights is 0, evaluated on drafts), `valueText(weight, share): string` ("0.4, 12% of the total"). Backend: `PATCH /api/settings/analyzers/<id>/` returns 400 `{ "weight": ["..."] }` when the update would leave every active analyzer with weight 0 (the analyzer being edited counts with its new weight; inactive analyzers are ignored; a deactivation path does not exist here).
- `ScoringTable` replaces `ScoringPanel`: MUI table (caption "Analyzer weights"), columns Analyzer (name + cortex id, "Inactive" text chip), Weight (slider with `aria-label="<name> weight"` and `aria-valuetext`, plus a number input 0-1 step 0.1), Share of total (text), State ("Modified" text + marker); toolbar with search, "Modified only" toggle (`aria-pressed`), sort by name/weight/share (`aria-sort` on headers); sticky action bar when anything is modified ("N unsaved changes", Reset to saved, Save all); explanation under the panel title: "Weights are relative. A case's score is the weighted average of the analyzers that ran on it, so changing one weight changes every analyzer's share." ; neutral colours only (no red/green).

- [ ] **Step 1: Failing tests (frontend):** `weights.ts` (shares sum to 1 over all listed analyzers, zero-sum -> 0 each, inactive analyzers are in `shares` but excluded from `wouldZeroTotal`; tests pin both), search filters by name and cortex id, "Modified only", each sort direction and `aria-sort`, slider and number input stay in sync and clamp to 0-1 and one decimal, `aria-valuetext` content, Save all with one of three failing: real counts, the failed row stays Modified, no unhandled rejection; Save refused with an inline error when all active drafts are 0 (no request sent); one analyzer at 0 is allowed; Reset to saved; Save with nothing modified says "Nothing to save"; `useReportUnsaved("scoring", dirty)` true while modified and false after save; no literal red/green hex in styles; 26 rows render within the test time budget.
- [ ] **Step 2: Failing tests (backend)** in `api/tests/test_analyzer_settings.py`: all other active analyzers 0 and new weight 0 -> 400; new weight 0 while another active analyzer has weight > 0 -> 200; inactive analyzer with weight > 0 does not rescue the sum; weight 0.0 on the only active analyzer -> 400; non-numeric/out of range still 400; non-Admin/CERT 403 unchanged.
- [ ] **Step 3: Run, verify fail; implement** `weights.ts`, `ScoringTable.tsx`, the view check (a small helper in the view module, one query: `Analyzer.objects.filter(is_active=True).exclude(pk=analyzer.pk).aggregate(Sum("weight"))`), docs line for the endpoint; remove `ScoringPanel.tsx` and update `sections.tsx`.
- [ ] **Step 4: Gates incl. backend `ww test backend api dashboard`; commit** `feat(ui): analyzer scoring as a searchable table with shares and a weight-sum guard` (frontend and backend may be two commits).

### Task 4: Connectors

**Interfaces (produces):** `labels.ts`: `fieldLabel(field: ConfigField): string` (schema `label` if present, else de-snaked title case with an acronym map `url->URL, api->API, id->ID, ip->IP, ssl->SSL, tls->TLS, smtp->SMTP, imap->IMAP`, so `ollama_url` -> "Ollama URL"), `cleanDescription(text: string): string` (removes a trailing sentence that starts with "See " and references a path under `docs/`, leaves other text untouched).

- [ ] **Step 1: Failing tests:** `fieldLabel` (acronyms, multiple words, already-labelled field, the raw key appears as helper text); `cleanDescription` (strips "See docs/specs/2026-09-21-ai-narration-event-wiring-design.md.", keeps descriptions without it, keeps "See" sentences that are not doc paths); `ConnectorDetail`: Test connection failure shows an error alert with the detail (and a thrown request error is handled, not unhandled); Save failure keeps the draft and the form values; deliveries show a status word beside the dot (`delivery.status`), up to 10 with a note "Showing the last 10" when 10 are returned; draft present -> `useReportUnsaved("connectors", true)` and the nav marker; leaving with a draft goes through the unsaved confirm; Save disabled has a stated reason (`aria-describedby`: "No changes to save"); `ConnectorList` toggle names ("Enable <name>") unchanged, status text label present beside the dot.
- [ ] **Step 2: Run, verify fail. Step 3: Implement** in `ConnectorDetail.tsx`, `ConnectorList.tsx`, `configFieldHelpers.tsx`, `labels.ts`; `testConnector` gets `onError`; deliveries limit 10.
- [ ] **Step 4: Gates; commit** `fix(ui): settings connectors readable labels, delivery statuses and handled test failures`.

### Task 5: Polish and verification

- [ ] **Step 1: Failing tests** for what the keyboard-only and heading-outline pass finds: one h1, h2 per panel, no skipped level; unique region names; the table has a name; tab order nav -> status strip -> panel; confirm dialog focus return in each flow; reduced motion (no transitions when `prefers-reduced-motion`); every interactive control has an accessible name (axe-like assertions over the rendered page, as in `CampaignsPage.a11y.test.tsx`).
- [ ] **Step 2: Contrast sweep** (Playwright, all themes the app offers, 1440 and 390, every visible text node of every section; marks 3:1); reuse the Campaigns sweep script from `$CLAUDE_JOB_DIR/tmp` if present; fix page-owned failures with `ensureContrast`; list shared failures without changing them; save the table under the sdd directory and copy a summary to `docs/plans/settings-contrast-2026-10.tsv` (columns: theme, viewport, section, element, fg, bg, ratio, required, owner(page|shared), status; one counting rule on every summary row).
- [ ] **Step 3: Final verification:** full vitest, `tsc -b`, eslint, backend `ww test backend api dashboard`, e2e 7/7, `investigation.spec.ts` vs main's 2 failures; rebuild the Docker images, capture every section in 5 themes at 1440 and 390 (and one failure state: a failing bulk delete) and view them; anti-slop delivery report (claims with a source, no fabricated content, decisions with a one-line reason, everything run, UI strings and comments); append backlog entries to `docs/plans/ui-redesign-backlog.md` (tier field not editable in the UI; connector `description` copy owned by the connectors; global unsaved-changes pattern for Profile; ConfirmDialog reuse); commit `fix(ui): settings accessibility and contrast`.

## Self-review

- Spec coverage: navigation, header, status strip (Task 1); confirmations, undo, batch honesty, unsaved guard, feeder (Tasks 1-2); scoring table, shares, explanation, zero guard UI + API (Task 3); connector labels, deliveries, test failures, description copy (Task 4); contrast sweep, a11y, verification (Task 5).
- Placeholders: none; each task lists its assertions and interfaces name signatures.
- Type consistency: `SectionKey`, `useReportUnsaved`, `runBatch`, `ConfirmDialog`, `shares/wouldZeroTotal` named identically wherever used.
- Open question for Task 3 ruled here: shares are computed over all listed analyzers (the page cannot know which analyzers ran on a case), the zero guard over active analyzers only (inactive ones are not scheduled).
