# Investigation Page Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the analyst page the same readable list and the case-sheet drawer as Submissions, with the analyst's decision (verdict, real explanation, override, push) first and the actions grouped sensibly.

**Architecture:** Reuse the building blocks from the Submissions cycle (collapsible filters pattern, `TablePagination`, `RecentSubmissionsList` + `CalmStatusChip`, `EmptyState`, the drawer's tabs, header band, `tabColors`, `ensureContrast`, `isElevatedGroups`); extract the Investigation drawer from `pages/InvestigationPage.tsx` into `features/investigation/components/InvestigationDrawer.tsx`, then redesign it in place. No backend change.

**Tech Stack:** React 19, MUI 9.4, react-router 8, TanStack Query 5, Vitest 4 browser mode, Playwright.

**Spec:** the approved chat design of 2026-10-09 (audit V1 to V6; user: "do what you recommend": primary header actions = Edit verdict and Push to TheHive; Full report, Markdown, Copy link and Redo analysis in a More menu with Redo keeping its confirmation dialog). Bounded change to an existing page: no separate spec file.

## Design direction

- **Same case-sheet language as the Submissions drawer** so analysts and reporters see one system: sticky header with a 3px accent in the verdict colour (`useResultHex`), ID with copy and previous/next, one verdict chip, a quiet meta line (status · type · tests · date), then tabs.
- **Tabs: Overview, Analysis (n), Discussion (n), Raw.** Overview is the decision sheet in this order: (1) allow/deny-list banner and the analysis-health banner (they qualify the verdict, so they sit above it), (2) verdict block (classification chip, score/confidence stat blocks where the IOC road shows them: keep the existing rule that the IOC road has no analyst-visible score and uses `ThreatBadge`), (3) the real "Why this verdict" (`VerdictExplanation`, the backend `verdict_explanation`) with its source breakdown, (4) reporter's challenge (proposed verdict) and reporter's context, (5) "Verdict override" panel (Edit mode kept), (6) artifact and reporter (with copy), (7) email preview (mail cases only), (8) page screenshot ONLY when a screenshot exists. Analysis keeps the observable-group panel and the analyzer groups, with the honest status labels from the Submissions cycle (Failed / Running / Queued / Expired / Unknown) and groups sorted by worst risk. Discussion hosts `CommentThread`. Raw hosts today's raw payload accordion.
- **Actions:** header shows two primary buttons: "Edit verdict" (switches to Overview and focuses the override panel; keeps today's edit flow) and "Push to TheHive" (only when the TheHive connector is enabled, as today); a "More" menu holds "Full report", "Markdown report", "Copy link", "Redo analysis" (opens the existing confirmation dialog). On phones the two primary buttons stay in the header and More holds the rest.
- **List:** one search field plus a collapsible Filters panel (Status, Type, Result, From, To, Sort) with an active-count chip and Reset; `TablePagination` below the table (server-side paging stays: this page has no 100-row limit); header chip "<total> total"/"<n> match" using the server count; avatar removed; calmer rows (muted DONE via `CalmStatusChip`, lighter ID chip, artifact one line with ellipsis and title, copy icon on hover/focus-within and always on touch); phone list via `RecentSubmissionsList` showing the verdict and the reporter's mail; `EmptyState` for "no match" (with Clear filters) and "no cases yet".
- **Typography/contrast/motion:** theme variants only, `pageTitle` for the page title (already applied), `ensureContrast` for any new coloured text, no inline weight above 800 or letter-spacing, the global reduced-motion setting already exists.

## Global Constraints

- No route change, no new dependency, no backend change, theme tokens only (no hardcoded colours), every theme keeps its contrast floor. Elevated-only access stays as is (`ELEVATED_GROUPS` guard on the route).
- Every design decision has a one-line reason (anti-slop C-1); UI strings plain; only state what the page knows. Remove inline `letterSpacing` and `fontWeight` above 800 from every element you touch.
- Rulings carried over from the Submissions cycle: AI classifier with score 0 AND confidence 0 renders "Not classified"; report statuses: Success, Failure -> "Failed", InProgress -> "Running", Waiting -> "Queued", Deleted -> "Expired", anything else "Unknown", only "Failed" counts as failed; "No analyzers ran for this submission." only when status DONE, tests_done 0 and no reports; stat blocks show "—" when no analyzers ran; the multi-observable label ("Indicators") only for case type UNKNOWN.
- Frontend toolchain: Node 22 (`export PATH=$CLAUDE_JOB_DIR/tmp/node-v22.13.1-linux-x64/bin:$PATH`), `npx pnpm@11.1.3`, `npx vitest run`, `npx tsc -b`, `npx eslint .` (0 errors; 4 existing warnings fine). `suspicious-ui/.env` sets `VITE_SUSPICIOUS_EMAIL` (leaks into unit tests: `vi.stubEnv`). The page tests use `renderWithProviders`; Submissions tests use a `matchMedia` `stub` helper (desktop default): reuse its pattern.
- Visual check: `(cd deployment && docker compose --env-file .env build suspicious_ui && docker compose --env-file .env up -d suspicious_ui); sleep 8`, then a Playwright script under `$CLAUDE_JOB_DIR/tmp` (login as `scripts/theme-sheets.mjs`: `UI_USER=elena.voss@meridian.example UI_PASS='MeridianDev!2026'` (elena is CISO: elevated), `CHROMIUM_PATH=$(ls ~/.cache/ms-playwright/chromium_headless_shell-1234/*/chrome-headless-shell)`, theme via the `suspicious:theme-hydrate` window event). Dev cases: 202 total; #18 IOC group (Dangerous, 49 tests, six observables, 9 failed analyzers), #22 Suspicious, #21 file, #232 no analyzers, #324 and neighbours are MAIL cases (Dangerous). Baselines: `$CLAUDE_JOB_DIR/tmp/audit-inv`.
- e2e: `(npx vite --port 5173 > $CLAUDE_JOB_DIR/tmp/vite-e2e.log 2>&1 &); sleep 8; npx playwright test e2e/submit.spec.ts e2e/ioc-road.spec.ts --reporter=list --retries=0; pkill -f "vite --port 5173"` must stay 7/7; `e2e/investigation.spec.ts` has 2 known failures on main (do not worsen; if your changes make a failing test pass or a passing one fail, report it: update the spec only to follow deliberate markup changes).
- Never stage anything under `deployment/` (an unrelated uncommitted `compose_apps.yaml` edit lives there).

## Review Focus

- Deep link `/investigation?open=<id>`, Back closes the drawer, desktop row click, phone ID link (history-safe, `replace`), challenge/IOC flows unchanged. Pinned in Tasks 1 and 4.
- Verdict override: Edit/Save/Cancel, validation (score 0-10, confidence 0-100), optimistic state, the IOC-road rule (no analyst score), and permissions unchanged. Pinned in Task 2.
- Push to TheHive: only when the connector is enabled; pending/success/failure states unchanged. Pinned in Task 2.
- Redo analysis keeps its confirmation dialog and is reachable by keyboard from More. Pinned in Task 2.
- A case with 0 reports, a MAIL case, an IOC group of 49 reports, a details load failure. Pinned in Tasks 2 and 3.

---

## File Structure

- Create `features/investigation/components/InvestigationDrawer.tsx` (+ tests), `InvestigationOverview.tsx`, `InvestigationAnalysisTab.tsx`, `InvestigationActions.tsx` as the tasks need.
- Modify `pages/InvestigationPage.tsx` (drawer markup replaced by the component; list changes), `pages/__tests__/InvestigationPage.test.tsx`, `features/investigation/components/InvestigationAnalyzerReportCard.tsx`, maybe `features/home/components/RecentSubmissionsList.tsx` (an optional prop for a second meta line, backward compatible).

---

### Task 1: Extract the drawer (no behaviour change)

**Files:** create `features/investigation/components/InvestigationDrawer.tsx`; modify `pages/InvestigationPage.tsx`.

- [ ] **Step 1:** run `npx vitest run src/pages/__tests__/InvestigationPage.test.tsx src/features/investigation` and record the pass count (all green baseline).
- [ ] **Step 2:** move the `<Drawer ...>` block (~line 835 through its closing tag) and the redo-confirm `<Dialog>` stays in the page; the drawer receives what it needs by props (exported props type, smallest set; pass queries/mutations/handlers; the page keeps URL sync, `closeDrawer`, row selection, queries, mutations, `selectedRow` derivation). No visual or behavioural change: capture `/investigation?open=18` and `?open=232` at 1440 and 390 before and after in light and midnight and compare (identical expected); keep every existing test unchanged and green; add one small direct test file for the component (renders ID and Close; empty state "Select a row.").
- [ ] **Step 3:** `npx vitest run`, `npx tsc -b`, `npx eslint .`. Commit `refactor(ui): extract the investigation drawer into its own component`.

---

### Task 2: Header band, actions and Overview tab

**Files:** `InvestigationDrawer.tsx`, create `InvestigationOverview.tsx`, `InvestigationActions.tsx`, `pages/InvestigationPage.tsx` (wiring), tests.

Build per Design direction: header band, tabs scaffold (Analysis, Discussion and Raw panels first render today's blocks unchanged), the Overview order listed above, the actions (two primary buttons plus More menu; keep today's mutations/confirmation dialog; "Edit verdict" scrolls/focuses the override panel and enters edit mode), "Copy link" (`<origin>/investigation?open=<id>` with the same try/catch + snackbar as the Submissions drawer: reuse its helper if extracted, else mirror), Full report/Markdown URLs as today, screenshot block only when `screenshot_url` exists, the "Not classified" rule, the "—" stats rule when no analyzers ran, shared `isElevatedGroups` unaffected.

- [ ] **Step 1: Failing tests** (read `pages/__tests__/InvestigationPage.test.tsx` and the Submissions drawer tests for patterns): header shows the ID once and one verdict chip; meta line; tablist "Overview, Analysis (n), Discussion (n), Raw"; Overview section order (assert DOM order of the headings); the real explanation text is shown from `verdict_explanation`; health and allow/deny banners appear BEFORE the verdict block; primary buttons "Edit verdict" and "Push to TheHive" (the latter only when the connector query says enabled; absent otherwise); More menu items and that "Redo analysis" opens the existing dialog and Cancel closes it; "Copy link" success and failure snackbars; screenshot block absent without `screenshot_url`, present with it; AI "Not classified"; stats "—" when nothing ran; Edit flow unchanged: Save sends the same payload (assert the mutation call), validation messages for out-of-range values.
- [ ] **Step 2: Implement; run to pass; visual check** at 1440 and 390 in light, midnight, paper, high_contrast, cyber for #18, #22, #324 (mail), #232; view them all and iterate.
- [ ] **Step 3:** `npx vitest run`, `npx tsc -b`, `npx eslint .`, e2e 7/7. Commit `feat(ui): case-sheet header, actions menu and overview for the investigation drawer`.

---

### Task 3: Analysis, Discussion and Raw tabs

**Files:** create `InvestigationAnalysisTab.tsx`, modify `InvestigationAnalyzerReportCard.tsx`, `ObservableGroupPanel.tsx`/`SourceTable.tsx` only as needed, tests.

Build: Analysis tab keeps the IOC `ObservableGroupPanel` (VT-style) and the analyzer groups; groups sorted by worst risk with a worst-risk dot, analyzer count and "<n> failed" (only Failed); rows compact with a left risk edge and ONE risk chip; failed/running/queued/expired/unknown rows neutral dashed (labels per the carried-over rulings); confidence only when expanded; the worst-risk group starts open; "Expand all"/"Collapse all" icon buttons with aria-labels; heading "Analysis" (`h3`) with the count as text, hidden while loading/error; loading/error/empty states keep their exact texts; the `UrlGroupList`-equivalent analyze buttons (if this page has them) keep working. Prefer reusing the Submissions `AnalysisTab`/`AnalyzerReportCard` building blocks (`features/submissions/utils.ts` `unfinishedLabel`, `reportSucceeded`, shared `RiskChip`) over re-implementing; if the Investigation report type has extra enrichment (`AnalyzerEnrichment`), keep it inside the expanded row. Discussion tab: `CommentThread` unchanged. Raw tab: today's raw payload (monospace via `monoStack`, copy button if the old accordion had one).

- [ ] **Step 1: Failing tests:** group order by worst risk; failed row shows "Failed" and no risk chip; Deleted shows "Expired" (not counted failed); Running/Queued labels; worst group opens by default; expand/collapse all labels; reset when another case opens; Discussion shows the thread and the count; Raw shows the payload; loading/error/empty states exact texts; IOC panel present for an IOC case and absent for a mail case.
- [ ] **Step 2: Implement; run to pass; visual check** at 1440 and 390 in light, midnight, high_contrast, cyber for #18 (expanded all), #324, #22; view them.
- [ ] **Step 3:** `npx vitest run`, `npx tsc -b`, `npx eslint .`, e2e 7/7. Commit `feat(ui): investigation analysis, discussion and raw tabs`.

---

### Task 4: The list: filters, pager, rows, phone list, empty states

**Files:** `pages/InvestigationPage.tsx` (header ~485-530, filter card ~520-700, table ~710-830), possibly `features/home/components/RecentSubmissionsList.tsx`, tests.

Changes (each with its reason): (1) header chip "<total> total" when no search and no filter, "<n> match" with search or filters (server count: `investigationsQuery.data?.count`), the avatar removed; (2) filters: the search field always visible plus a "Filters" button (aria-expanded, aria-controls) that toggles a `Collapse` with Status, Type, Result, From, To, Sort; count chip of active non-default controls; Reset clears everything and shows only when something is active; (3) `TablePagination` below the table (`component="div"`, `count` = server total, rows per page 10/25/50, "x–y of N", `labelDisplayedRows`), hidden when total is 0; a filter change returns to page 1; phones: no overflow; (4) rows: muted DONE via `CalmStatusChip`, lighter outlined ID chip with copy icon, artifact one line with ellipsis and `title`, copy icon on hover/focus-within and always on touch, user mail column kept; (5) under `sm` render `RecentSubmissionsList` (ID link opens the drawer: `/investigation?open=<id>` with `replace`; verdict chip, artifact, status, type, date, and the reporter's mail as a second meta line through an OPTIONAL backward-compatible prop; Home and Submissions unchanged); (6) `EmptyState`: filtered "No cases match" with "Clear filters"; none at all "No cases yet" (hint without invented facts); (7) URL sync: closing the drawer drops `open` with `replace`; when `open` disappears from the URL (Back) the drawer closes; prev/next arrows move within the current page rows (disabled when the case is not on the page) like the Submissions drawer; (8) remove inline weight/letter-spacing on touched elements.

- [ ] **Step 1: Failing tests:** default view has search + Filters and no Status control; Filters toggles five controls; active count chip; Reset; header chip wording with a mocked server count (340 total vs 12 match); TablePagination below the table with 10/25/50 and absent for 0 results; filter change resets to page 1; phone viewport renders list items with ID link `href="/investigation?open=<id>"`, verdict text, reporter mail, no `table`; desktop renders the table; empty states with their actions; Back closes the drawer; prev/next disabled off-page. Keep existing tests green (adapt text/structure changes and list each).
- [ ] **Step 2: Implement; run to pass; visual check** at 1440 and 390 in light, midnight, paper, high_contrast, cyber: collapsed, expanded, filtered, page 2, phone list, empty; scrollWidth <= innerWidth at 390; view them.
- [ ] **Step 3:** `npx vitest run`, `npx tsc -b`, `npx eslint .`, e2e 7/7. Commit `feat(ui): investigation list with collapsible filters, bottom pager and phone list`.

---

### Task 5: Accessibility, contrast and final verification

- [ ] **Step 1: Accessibility (drawer and list):** named modal dialog (aria-labelledby the h2), heading outline (h2 ID, h3 sections), tabs/panels linkage, every icon button named, focus into the dialog on open and back to the opener on close, More menu keyboard flow (Enter/Escape, focus return), risk/status as text not colour alone. Tests for each.
- [ ] **Step 2: Contrast:** extend the measured contrast script (Playwright, `$CLAUDE_JOB_DIR/tmp`): for #18, #324, #232 in light, midnight, paper, high_contrast, cyber, metal, future at Overview and Analysis tabs: report every text with ratio < 4.5 (< 3 for large text) and FIX drawer/list-owned failures with `ensureContrast`; report shared-component failures without changing them.
- [ ] **Step 3:** full suite, `tsc -b`, `eslint .`, e2e 7/7 (+ `investigation.spec.ts` result vs main's 2 failures), final captures of list and drawer at 1440/390 for five themes (view them), anti-slop delivery report (PASS/FAIL with evidence for: claims without a source, fabricated content, decisions without a reason, anything delivered without being run, UI strings and comments), backlog append, `mem_save` by the controller. Commit.

---

## Self-review

- **Spec coverage:** V1 and V5 Task 2 (Overview order, banners above the verdict); V2 Task 2 (actions); V3 Task 2 (no duplicate tile, "Not classified"); V4 Task 2 (screenshot only when present); V6 Task 4 (list); honesty rules carried to Tasks 2 and 3; accessibility and contrast Task 5.
- **Placeholders:** none: where a task depends on existing code details it names the file and lines to read first.
- **Type consistency:** `InvestigationDrawer` is introduced in Task 1 and extended in Tasks 2 and 3; tab names (Overview, Analysis, Discussion, Raw) are identical everywhere; `RecentSubmissionsList` gains one optional prop only.
