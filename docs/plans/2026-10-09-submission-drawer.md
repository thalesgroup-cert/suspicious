# Submission Drawer Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Submissions detail drawer into a readable "case sheet": one clear verdict, honest sources, a short list of why, analysis sorted by risk, and the actions a user actually needs.

**Architecture:** Extract the drawer from `SubmissionsPage.tsx` into `features/submissions/components/SubmissionDrawer.tsx` (behaviour-preserving move), then redesign it in place: header band, three tabs (Overview, Analysis, Comments), a "More" menu. No backend change.

**Tech Stack:** React 19, MUI 9.4 (Drawer, Tabs, Menu, Collapse), react-router 8, TanStack Query 5, Vitest 4 browser mode, Playwright.

**Spec:** the approved chat design of 2026-10-09 (audit D1 to D11; user: "go with your drawer plan", "design wise what do you give it?"). Bounded change to an existing component: no separate spec file.

## Design direction (what the drawer gets)

- **Case-sheet layout, verdict first.** A 3px accent line at the very top in the verdict's own colour (theme result colours via `useResultColors`, so user colour settings and every theme are honoured). The ID is large with a copy button; the verdict is the one large chip under it; status, type, test count and date become a quiet one-line meta text ("Done · Indicators · 49 tests · Sep 21, 2026"), not four more chips. Reason: the old header repeated the same facts in chips, a tile and a verdict block.
- **Three tabs under the sticky header: Overview, Analysis (n), Comments (n).** MUI `Tabs`, scrollable on phones, counts as plain text in the label. Reason: 49 reports and a comment box in one scroll buried the answer; the reporter needs the verdict and the why first.
- **Overview:** Score and Confidence as two stat blocks (large number, thin bar in the verdict colour); "Why this verdict" = up to three highest-risk analyzer results by name with their risk label (data already on the page, link "See all N in Analysis"); "Sources" labels the case verdict and the AI classifier (shown as "Not classified" when score and confidence are both 0); the artifact in a monospace block with copy (for multi-observable cases the section is titled "Summary" and shows the summary sentence plus "<n> observables", never an `UNKNOWN` type).
- **Analysis:** groups sorted by worst risk; each group header shows its worst-risk dot and "n failed" when any; analyzer rows are compact (name, result, one risk chip; a left edge in the risk colour); failed analyzers read "Failed" in a neutral dashed chip, never "Low risk"; confidence is shown on expand only; "Expand all / Collapse all" become icon buttons with labels and proper hit areas.
- **Actions:** primary "Full report" stays visible; a "More" menu holds "Markdown report", "Copy link", "Open in Investigation" (elevated users only), "Challenge" (when eligible); previous/next arrows move to the adjacent row of the current page.
- **Typography and motion:** theme variants only (no inline weight/letter-spacing), `pageTitle`-consistent scale, monospace token exported from `themes.ts` for artifacts/hashes; MUI `Collapse` for expansion (reduced motion is honoured by the global `prefers-reduced-motion` rule in `AppThemeProvider`, not by MUI itself), no new animation dependency.
- **Phone:** full-screen sheet (Task 2 of the Submissions plan already keeps the header sticky), tabs scroll horizontally, no horizontal page scroll.

## Global Constraints

- No route change, no new dependency, no backend change, theme tokens only (no hardcoded colours), every theme keeps its contrast floor.
- Every design decision has a one-line reason (anti-slop C-1); UI strings plain; only state what the page knows. Remove inline `letterSpacing` and `fontWeight` above 800 on every element you touch.
- Rulings already made: (1) AI classifier with score 0 AND confidence 0 renders "Not classified" (muted); otherwise as today. (2) "No analyzers ran for this submission." keeps its Task-6 rules (status DONE, tests_done 0, no reports). (3) "Open in Investigation" only for elevated users (CISO/CERT/Admin as `AppLayout` computes `isElevated`).
- Frontend toolchain: Node 22 (`export PATH=$CLAUDE_JOB_DIR/tmp/node-v22.13.1-linux-x64/bin:$PATH`), `npx pnpm@11.1.3`, `npx vitest run`, `npx tsc -b`, `npx eslint .` (0 errors; 4 existing warnings fine). `suspicious-ui/.env` sets `VITE_SUSPICIOUS_EMAIL`, which leaks into unit tests (`vi.stubEnv` + `vi.unstubAllEnvs`). The SubmissionsPage tests use a `matchMedia` `stub` helper (desktop by default).
- Visual check: `(cd deployment && docker compose --env-file .env build suspicious_ui && docker compose --env-file .env up -d suspicious_ui); sleep 8`, then a Playwright script under `$CLAUDE_JOB_DIR/tmp` (login as `scripts/theme-sheets.mjs`: `UI_USER=elena.voss@meridian.example UI_PASS='MeridianDev!2026'`, `CHROMIUM_PATH=$(ls ~/.cache/ms-playwright/chromium_headless_shell-1234/*/chrome-headless-shell)`, theme via the `suspicious:theme-hydrate` window event). Dev cases with analyses: #18 (Dangerous, 49 tests, 6 observable groups, one failed analyzer), #22 (Suspicious, 40 tests), #21 (a file, Safe, 1 test); #232 has 0 tests. Baselines: `$CLAUDE_JOB_DIR/tmp/audit-drawer` and `audit-subs`.
- e2e: `(npx vite --port 5173 > $CLAUDE_JOB_DIR/tmp/vite-e2e.log 2>&1 &); sleep 8; npx playwright test e2e/submit.spec.ts e2e/ioc-road.spec.ts --reporter=list --retries=0; pkill -f "vite --port 5173"` must stay 7/7 (login 4 and investigation 2 fail on main already; do not worsen).
- Never stage anything under `deployment/` (an unrelated uncommitted `compose_apps.yaml` edit lives there).

## Review Focus

- Deep link `/submissions?open=<id>` and phone ID links still open the drawer; Back closes it; desktop row click still works. Pinned in Task 1.
- A case with 0 reports, 1 report, 49 reports across 6 groups; a case whose details fail to load. Pinned in Tasks 2 and 3.
- Keyboard: tabs reachable with arrow keys, More menu opens/closes with Enter/Escape and returns focus, Escape closes the drawer, focus is trapped. Pinned in Tasks 4 and 5.
- A reporter (non-elevated) never sees "Open in Investigation". Pinned in Task 4.
- Prev/next at the first/last row of the page are disabled, not wrapping. Pinned in Task 4.

---

## File Structure

- Create `features/submissions/components/SubmissionDrawer.tsx` (+ `__tests__/SubmissionDrawer.test.tsx`), `features/submissions/components/AnalysisTab.tsx`, `OverviewTab.tsx`, `DrawerActions.tsx` as the tasks need (one responsibility each).
- Modify `pages/SubmissionsPage.tsx` (drawer markup removed, replaced by `<SubmissionDrawer … />`), `features/submissions/components/AnalyzerReportCard.tsx`, `shared/components/SheetHeader.tsx` only if the header band needs it, `styles/themes.ts` (export `monoStack`).
- Tests: `pages/__tests__/SubmissionsPage.test.tsx` (drawer tests move or stay: keep them passing).

---

### Task 1: Extract the drawer (no behaviour change)

**Files:** create `features/submissions/components/SubmissionDrawer.tsx`; modify `pages/SubmissionsPage.tsx`.

**Interfaces:** Produces `SubmissionDrawer(props: { open: boolean; onClose: () => void; row: SubmissionRow | null; details: UseQueryResult<SubmissionDetails>; comments: { query: UseQueryResult<...>; add: (body: string) => Promise<unknown>; isAdding: boolean }; ... })`: read the drawer block (`<Drawer ...>` through its closing tag, ~lines 809-1090 of `pages/SubmissionsPage.tsx`) and the state/handlers it uses (`expandedGroups`, `reportGroups`, `analyzerReports`, `ci`, `noAnalyzersRan`, `setChallengeId`, `commentsQuery`, `addCommentMutation`) and choose the smallest props set; derived values may move into the component.

- [ ] **Step 1:** Run the SubmissionsPage tests and note the count (baseline, all green).
- [ ] **Step 2:** Move the drawer JSX and its drawer-only state into `SubmissionDrawer`; keep every test unchanged and green; the page keeps owning URL sync, `closeDrawer`, row selection and the challenge dialog. No visual or behavioural change: capture `/submissions?open=18` at 1440 and 390 before and after and compare.
- [ ] **Step 3:** `npx vitest run`, `npx tsc -b`, `npx eslint .`. Commit `refactor(ui): extract the submission drawer into its own component`.

---

### Task 2: Header band and Overview tab

**Files:** `SubmissionDrawer.tsx`, create `OverviewTab.tsx`, `themes.ts` (export `monoStack`), tests.

Changes (see Design direction): verdict accent line + ID + single verdict chip + one-line meta text (status, type label "Indicators" when the case has more than one observable or type is UNKNOWN, tests, date); tabs scaffold (Overview, Analysis (n), Comments (n); content for Analysis and Comments moves in Task 3 and 4: for now render today's analysis and comments blocks under their tabs); Overview content: Score and Confidence stat blocks with thin bars, "Why this verdict" (top three highest-risk analyzer results: reuse the risk tone helper `getRiskTone` used by `AnalyzerReportCard`; hide the block when there are no reports or no risk above low), "Sources" (Verdict, AI classifier, "Not classified" rule), artifact/summary block in monospace with copy, the "No analyzers ran" line per its rules, the email preview when present.

- [ ] **Step 1: Failing tests:** header shows the ID once and ONE verdict chip, no "UNKNOWN" text for a multi-observable case (label "Indicators"), meta line text present; Tabs: `getByRole("tablist")` with Overview selected, "Analysis (49)" and "Comments (0)" labels; Overview shows stat blocks "9/10" and "60%" for a case with score 9 and confidence 60; "Why this verdict" lists at most three analyzers ordered by risk and is absent for a case with no reports; AI classifier with score 0 and confidence 0 reads "Not classified"; artifact block copy button; for a multi-observable case the section title is "Summary" and carries the summary sentence.
- [ ] **Step 2: Implement; run to pass; visual check** at 1440 and 390 in light, midnight, paper, high_contrast, cyber for #18, #22, #232; view them all.
- [ ] **Step 3:** `npx vitest run`, `npx tsc -b`, `npx eslint .`. Commit `feat(ui): case-sheet header and overview tab for the submission drawer`.

---

### Task 3: Analysis tab

**Files:** create `AnalysisTab.tsx`, modify `AnalyzerReportCard.tsx`, `UrlGroupList.tsx` placement, tests.

Changes: groups sorted by worst risk (descending) with a worst-risk dot and "n failed" on each group header; compact analyzer rows (name, result subtitle, one risk chip, left edge in the risk colour); a failed analyzer shows "Failed" in a neutral dashed chip and no risk or confidence; confidence only on expand; "Expand all" and "Collapse all" as icon buttons with `aria-label` and a 32px+ hit area; URL groups (`UrlGroupList`) move under this tab; loading, error and empty states as today ("Loading analysis…", warning alert, "No analysis reports yet.").

- [ ] **Step 1: Failing tests** (build a detail fixture with 3 groups: one high-risk, one low, one with a failed analyzer): group order is by worst risk; the failed analyzer renders "Failed" and no "Low risk"; group header shows "1 failed"; expand all / collapse all via their aria-labels; loading and error states still render; a failed analyzer's risk chip is absent.
- [ ] **Step 2: Implement; run to pass; visual check** at 1440 and 390 in light, midnight, high_contrast for #18 with groups expanded; view them.
- [ ] **Step 3:** `npx vitest run`, `npx tsc -b`, `npx eslint .`. Commit `feat(ui): analysis tab sorted by risk with honest failed analyzers`.

---

### Task 4: Comments tab and the actions menu

**Files:** create `DrawerActions.tsx`, `SubmissionDrawer.tsx`, `pages/SubmissionsPage.tsx` (prev/next wiring), tests.

Changes: Comments tab hosts the existing `CommentThread` unchanged; actions: keep "Full report" (primary, opens `/api/cases/<id>/report/` as today), add a "More" icon menu (MUI `Menu`, `aria-haspopup`, returns focus to the trigger) with: "Markdown report" (same URL pattern as the Investigation page: `/api/cases/<id>/report.md`, read `pages/InvestigationPage.tsx` ~line 895), "Copy link" (copies `<origin>/submissions?open=<id>`, with a snackbar via `notistack` "Link copied"), "Open in Investigation" (elevated users only; the route and param the Investigation page reads; confirm by reading its URL handling), "Challenge" (only when the row passes the page's `canChallenge`, calls the existing `setChallengeId` flow); previous/next icon buttons in the header move to the adjacent row of the CURRENT page rows (disabled at the ends, no wrap) by navigating with `?open=<id>` (replace).

- [ ] **Step 1: Failing tests:** More menu items per role (reporter: Markdown report and Copy link only; elevated: plus Open in Investigation); Challenge item only for an eligible row and it opens the challenge dialog flow; Markdown item opens the expected URL (`window.open` spy); Copy link writes the expected URL to the clipboard; prev/next disabled at the ends and navigate to adjacent ids; Escape closes the menu and returns focus to the trigger.
- [ ] **Step 2: Implement; run to pass; visual check** at 1440 and 390 (menu open) in light and midnight; view them.
- [ ] **Step 3:** `npx vitest run`, `npx tsc -b`, `npx eslint .`. Commit `feat(ui): drawer actions menu, copy link and previous/next`.

---

### Task 5: Accessibility pass and final verification

- [ ] **Step 1: Accessibility:** the Drawer paper has `role="dialog"` with `aria-labelledby` pointing at the ID heading (`h2`) and `aria-modal`; section titles are real headings (h3) with theme typography, not inline-styled overlines; focus moves into the drawer on open and back to the opener on close (when opened from a row or link: if opened from a URL with no opener, focus the drawer heading); tabs use `aria-controls`/`id` pairs; all icon buttons have `aria-label`s; colour is never the only signal for risk (text label always present). Tests for the dialog name, heading levels, tab panel linkage and focus handoff.
- [ ] **Step 2:** full suite, `tsc -b`, `eslint .`, e2e 7/7; final captures of the drawer for #18, #22, #21, #232 at 1440 and 390 in light, midnight, paper, high_contrast, cyber (view them); contrast check of every text/background pair introduced (risk chips, stat bars, meta text) against 4.5:1 with a tool for high_contrast and cyber.
- [ ] **Step 3:** anti-slop delivery report: PASS or FAIL with evidence for claims without a source, fabricated content, decisions without a reason, anything delivered without being run, UI strings and comments.
- [ ] **Step 4:** append deferred items to `docs/plans/ui-redesign-backlog.md`; `mem_save` a short note. Commit.

---

## Self-review

- **Spec coverage:** D1 and D3 Task 2; D2 Task 2 ("Summary" section); D4 Task 2 ("Not classified"); D5 and D6 Task 3; D7 Tasks 2 and 3 (phone checks); D8 options Task 4; D9 unchanged (Full report URL kept); D10 Task 4 (Comments tab); D11 Task 5.
- **Placeholders:** none: where a task depends on existing code details it says which file and lines to read first.
- **Type consistency:** `SubmissionDrawer` is introduced in Task 1 and extended in Tasks 2 to 4; tab and component names are used identically.
