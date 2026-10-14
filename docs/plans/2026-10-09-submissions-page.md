# Submissions Page Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the unreachable Close button on phones, make the list readable on phones, simplify filters and paging, de-noise rows, make the detail drawer honest, and give every page one real page-title size.

**Architecture:** A new `pageTitle` typography variant in the base theme applied to every page title; a z-index fix in `AppLayout` plus a sticky-header phone sheet for the two page drawers; `SubmissionsPage.tsx` and `features/submissions/*` changes; reuse of the stacked list built for Home.

**Tech Stack:** React 19, MUI 9.4 (Table, TablePagination, Drawer, Collapse), react-router 8, TanStack Query 5, Vitest 4 browser mode, Playwright.

**Spec:** the approved chat design of 2026-10-09 (audit U1 to U10; decisions: "yes" to the zero-test wording and "yes" to a global page-title scale). Bounded change to existing pages: no separate spec file.

## Global Constraints

- No route change, no new dependency, theme tokens only (no hardcoded colours), every theme keeps its contrast floor (`contrast.test.ts` green).
- Every design decision has a one-line reason (anti-slop C-1); UI strings plain, no filler, no invented facts. Only state what the page knows (e.g. "No analyzers ran" only when `tests_done === 0`).
- Remove inline `sx` `letterSpacing` and `fontWeight` above 800 from every heading/title/label on the elements you touch (they caused the "Fileupload"/"Welcome,Elena" bugs); use typography variants.
- Frontend toolchain: Node 22 (`export PATH=$CLAUDE_JOB_DIR/tmp/node-v22.13.1-linux-x64/bin:$PATH`), `npx pnpm@11.1.3`, `npx vitest run`, `npx tsc -b`, `npx eslint .` (0 errors; 4 existing warnings fine). `suspicious-ui/.env` sets `VITE_SUSPICIOUS_EMAIL`, which leaks into unit tests (use `vi.stubEnv` + `vi.unstubAllEnvs`).
- Visual check: `(cd deployment && docker compose --env-file .env build suspicious_ui && docker compose --env-file .env up -d suspicious_ui); sleep 8`, then a Playwright script under `$CLAUDE_JOB_DIR/tmp` (login as `scripts/theme-sheets.mjs` does: `UI_USER=elena.voss@meridian.example UI_PASS='MeridianDev!2026'`, `CHROMIUM_PATH=$(ls ~/.cache/ms-playwright/chromium_headless_shell-1234/*/chrome-headless-shell)`, theme via the `suspicious:theme-hydrate` window event). Baselines before any change: `$CLAUDE_JOB_DIR/tmp/audit-subs` (list light/midnight desk+phone, drawer, empty, drawer-bottom).
- e2e: `(npx vite --port 5173 > $CLAUDE_JOB_DIR/tmp/vite-e2e.log 2>&1 &); sleep 8; npx playwright test e2e/submit.spec.ts e2e/ioc-road.spec.ts --reporter=list --retries=0; pkill -f "vite --port 5173"` (known: login.spec 4 and investigation.spec 2 fail on main already; do not fix, do not worsen). Loose `getByText` regexes break when copy changes: use roles/ids.
- Never stage anything under `deployment/` (an unrelated uncommitted `compose_apps.yaml` edit lives there).

## Review Focus

- Phone drawer: Close reachable, focus trap works, Escape and backdrop close, nav drawer still closes after the z-index change. Pinned in Task 2.
- A 390px row with a 64-char hash and a long URL: no horizontal page scroll. Pinned in Task 3.
- Filters from the URL (`?q=`, status, etc.): a filter applied via URL or while the disclosure is collapsed is still visible as a chip count and clearable. Pinned in Task 4.
- Page 2 of results, then a filter change: page resets to the first; rows-per-page change keeps position sensible. Pinned in Task 4.
- A drawer for a submission with `tests_done === 0` and one with analyses: the wording differs correctly. Pinned in Task 6.

---

## File Structure

- Modify `suspicious-ui/src/styles/themes.ts`, `styles/__tests__/themes.test.ts`; create `styles/typography.d.ts` (module augmentation).
- Modify each page's title element: `pages/HomePage.tsx`, `SubmitPage.tsx`, `SubmissionsPage.tsx`, `InvestigationPage.tsx`, `SettingsPage.tsx`, `ProfilePage.tsx`, `AboutPage.tsx`, and Dashboard/Campaigns titles (find with captures).
- Modify `layouts/AppLayout.tsx` (mobile app bar z-index).
- Create `features/submissions/components/DetailDrawer.tsx` or `shared/components/SheetHeader.tsx` (sticky drawer header) as the implementer finds smallest.
- Modify `pages/SubmissionsPage.tsx`, `features/submissions/components/*`, `pages/__tests__/SubmissionsPage.test.tsx`.

---

### Task 1: One page-title size for every page

**Files:** `styles/themes.ts` (`base.typography`), create `styles/typography.d.ts`, `styles/__tests__/themes.test.ts`, the title element of every page listed above and their tests if they assert the title.

**Interfaces:** Produces `variant="pageTitle"` for `Typography` (theme variant: 22px, weight 750, lineHeight 1.2, letterSpacing 0; inherits each theme's fontFamily; themes that set their own sizes for headings may set `pageTitle` too).

- [ ] **Step 1: Failing test.** In `themes.test.ts`: for every theme, `theme.typography.pageTitle` exists with computed fontSize between 20px and 28px (rem string x 16 as in the existing heading tests) and fontWeight <= 800; fails now (undefined).
- [ ] **Step 2: Implement per MUI docs** (customization, typography, adding variants): add `pageTitle` to `base.typography`; module augmentation in `typography.d.ts` (`TypographyVariants`, `TypographyVariantsOptions`, and `TypographyPropsVariantOverrides` with `pageTitle: true`); confirm `mergeTypography` carries it to themes that override typography blocks; `metal` and `future` call `createTheme` directly: give them the variant explicitly. Reason: one scale beats per-page inline overrides, and the title stays distinct from card titles (h5 14px).
- [ ] **Step 3: Apply.** Replace each page title element (`variant="h4"` / the Home greeting `h2`) with `variant="pageTitle"` plus `component="h1"` and remove its inline `fontWeight`/`letterSpacing`. Find every page title by grep for the page's title text and by viewing captures of each route (Dashboard and Campaigns titles may use other markup). Change only the title element on each page. Pages' own tests that assert title text keep passing; add one assertion that Submissions' title has computed font-size >= 20px.
- [ ] **Step 4: Visual check:** capture Home, Submit, Submissions, Investigation, Dashboard, Campaigns, Settings, Profile, About at 1440 in light, midnight, paper, high_contrast, cyber; view them; titles must be visibly larger than card titles and not wrap badly at 390 in light.
- [ ] **Step 5:** `npx vitest run`, `npx tsc -b`, `npx eslint .`. Commit `feat(ui): one page-title scale (pageTitle variant) for every page`.

---

### Task 2: Phone drawer reachable (sticky header, z-index root cause)

**Files:** `layouts/AppLayout.tsx` (~line 348), `pages/SubmissionsPage.tsx` (Drawer ~780, header), `pages/InvestigationPage.tsx` (Drawer ~834, header), tests.

- [ ] **Step 1: Reproduce.** At 390 open `/submissions?q=232&open=232` and `/investigation` (CERT user: elena is CISO/elevated; open a case): the app bar covers the drawer top; Close not clickable. Record `getBoundingClientRect` of the Close button and the app bar.
- [ ] **Step 2: Failing test(s).** A browser-mode test mounting the page drawer at a phone viewport inside AppLayout is heavy; instead pin the cause: in a unit test render `AppLayout`'s mobile AppBar and a `Drawer open` and assert the AppBar's computed z-index is lower than the Drawer paper's (use the real theme). If AppLayout is hard to mount in isolation, assert on the `zIndex` function result: `appBarZ < theme.zIndex.drawer`.
- [ ] **Step 3: Implement.** Change the mobile AppBar to `zIndex: (t) => t.zIndex.appBar` (1100), below modal drawers (1200). Verify the mobile NAV drawer still opens and closes (hamburger, backdrop click, Escape) and nothing else relied on the bar covering it. Page drawers on phones: full width (already), header row `position: sticky; top: 0` with the Close button always visible, `paddingTop: env(safe-area-inset-top)`; content scrolls under it. Apply the same header treatment to Submissions and Investigation drawers through one small shared component if the headers are alike (read both first), else do both inline and say why.
- [ ] **Step 4: Visual/functional check at 390** in light and midnight: drawer top fully visible, Close and Full report clickable (Playwright `click()` without force), Escape closes, focus returns to the row/ID that opened it; nav drawer open/close works. Same for Investigation (view only).
- [ ] **Step 5:** `npx vitest run`, `npx tsc -b`, `npx eslint .`. Commit `fix(ui): phone drawers sit above the app bar and keep Close reachable`.

---

### Task 3: Phone list for Submissions

**Files:** `pages/SubmissionsPage.tsx` (table block ~600-780), possibly move/reuse `features/home/components/RecentSubmissionsList.tsx`, tests.

**Interfaces:** Consumes `RecentSubmissionsList({ rows, hrefFor })` (ID link left, `ResultChip` right, artifact one line with ellipsis, status chip + type + date). Under `sm` Submissions renders it with `hrefFor = (r) => "/submissions?q=<id>&open=<id>"` (encode with `encodeURIComponent`, same as Home); from `sm` up the table stays.

- [ ] **Step 1: Failing tests:** at a phone viewport (use `useMediaQuery` mock or a matchMedia stub as Home's tests do; read `pages/__tests__/HomePage.test.tsx`) the page renders list items with ID link and verdict text and no `table`; at desktop the table renders. Review Focus pin: 64-char hash row has ellipsis styles.
- [ ] **Step 2: Implement.** If the Submissions row type differs from Home's `SubmissionRow`, map it (do not widen the Home type with page-specific fields). Keep opening the detail drawer from `?open=`. If importing across feature folders looks wrong, move the component to `shared/components/SubmissionList.tsx` and re-export from the old path (one commit-sized move; update the import in HomePage).
- [ ] **Step 3: Visual check at 390:** list shows verdicts, no horizontal page scroll (`scrollWidth <= innerWidth`).
- [ ] **Step 4:** `npx vitest run`, `npx tsc -b`, `npx eslint .`. Commit `feat(ui): stacked submissions list on phones`.

---

### Task 4: Filters, paging, header

**Files:** `pages/SubmissionsPage.tsx` (header ~398-420, filter card ~440-600), tests.

Changes (each with its reason):
1. Filters: one search field always visible; a "Filters" button toggling a `Collapse` that holds Status, Type, Result, From, To, Sort; the button shows an active-filter count chip (count of non-default among those six plus nothing for search); Reset clears all including search. Filters applied from the URL open the disclosure by default when any is active. Reason: seven always-open controls pushed the list down.
2. Paging: replace the top "Showing / Rows / Prev / Next" with MUI `TablePagination` placed OUTSIDE (below) the table, `rowsPerPageOptions={[10, 25, 50]}`, and `labelDisplayedRows` "x-y of N"; also on phones. Changing any filter resets to page 1. Reason: a pager scrolls away when it is part of the table, and was only at the top.
3. Header: remove the avatar next to the title; title uses `pageTitle` (done in Task 1, keep); the count chip reads "<total> total" and, when filtered, "<n> match"; remove the "Search: …" chip duplicate if the field already shows it. Reason: "99 shown" was the total while 10 were shown.

- [ ] **Step 1: Failing tests** (read the existing `SubmissionsPage.test.tsx` mocking style): default view shows search field, a "Filters" button and no Status select; clicking Filters shows the five controls; with `?` params applied (find how the page reads filters: `useSearchParams` only reads q/open today; if filters are state-only, test state) the active count chip appears; Reset clears; TablePagination present below the table with the rows-per-page options; changing a filter resets to page 1 (mock API returns page 2 then verify the request params); the count chip wording.
- [ ] **Step 2: Implement; run to pass.** `npx vitest run src/pages/__tests__/SubmissionsPage.test.tsx`.
- [ ] **Step 3: Visual check:** 1440 and 390 in light, midnight, paper, high_contrast: collapsed and expanded; view them.
- [ ] **Step 4:** `npx vitest run`, `npx tsc -b`, `npx eslint .`. Commit `feat(ui): collapsible filters, bottom pager, honest count`.

---

### Task 5: Row clarity

**Files:** `pages/SubmissionsPage.tsx` (table rows ~622-780), `features/submissions/*` if helpers live there, tests.

Changes: (1) Challenge column only when at least one row on the current page has a challenge value other than "Not available" (read how the value is derived); (2) artifact cell: single line with ellipsis (`maxWidth` with `minWidth: 0`), `title` attribute with the full value, copy icon appears on row hover/focus; (3) Status "DONE" rendered as a neutral/muted chip, active or failed states keep colour (read `StatusChip` and the statuses; do not change the shared StatusChip used elsewhere: wrap or pass a prop only if it already supports it, else style at the call site); (4) ID chip: the page's ID cell uses a lighter chip (outlined primary) with the copy icon; (5) No-results: replace the info Alert with `EmptyState` (title "No submissions match", hint "Try a different search or clear the filters.", action `Clear filters` button that resets filters); when the user has no submissions at all and no filter is active: title "No submissions yet", action link to `/submit`. Reason: de-noise rows, make the next action obvious.

- [ ] **Step 1: Failing tests:** Challenge header absent when no row has one, present when one does; artifact cell has ellipsis styles and full text in `title`; DONE chip not rendered with the success colour while a SAFE verdict chip is; empty states (filtered vs none at all) with their actions; Clear filters resets.
- [ ] **Step 2: Implement; run to pass; visual check at 1440 and 390 in light, midnight, paper, high_contrast, cyber.**
- [ ] **Step 3:** `npx vitest run`, `npx tsc -b`, `npx eslint .`. Commit `feat(ui): calmer rows, conditional challenge column, actionable empty states`.

---

### Task 6: Honest detail drawer

**Files:** `pages/SubmissionsPage.tsx` (Drawer content ~800-1100), `features/submissions/components/*`, tests.

Changes: (1) the header block shows the ID once: remove the duplicate "SUBMISSION #id" meta tile, keep Tests run and Submitted; (2) verdict section: label sources: "Verdict" (the result chip, score, confidence) and, if present, "AI classifier" with its label/score/confidence in `caption`-size chips no smaller than 12px (theme `caption`), so SAFE next to SUSPICIOUS reads as two named sources, not a contradiction; (3) when `tests_done === 0`, a neutral line under the verdict: "No analyzers ran for this submission." (no claim about why); (4) "Analysis · 0 reports" block: when there are 0 reports and tests_done is 0 show nothing extra (the line above covers it); when there are reports keep today's behaviour; (5) remove inline weight/letterSpacing in the drawer.

- [ ] **Step 1: Failing tests:** the drawer for a mocked detail with `tests_done: 0` shows the "No analyzers ran" line and "Verdict" and "AI classifier" labels; with `tests_done: 3` it does not show the line; the id text appears once in the header region (count matches); AI chips have computed font-size >= 12px.
- [ ] **Step 2: Implement; run to pass; visual check at 1440 and 390 (drawer) in light, midnight, high_contrast.**
- [ ] **Step 3:** `npx vitest run`, `npx tsc -b`, `npx eslint .`. Commit `feat(ui): drawer names its verdict sources and says when no analyzers ran`.

---

### Task 7: Final verification and delivery report

- [ ] **Step 1:** full frontend suite, `tsc -b`, `eslint .`, e2e (submit, ioc-road: 7/7), backend untouched (state it).
- [ ] **Step 2:** final captures of Submissions (list, filters expanded, drawer, empty) at 1440 in all 17 themes and at 390 for four, compare with `audit-subs`; and title captures of every page (Task 1).
- [ ] **Step 3:** anti-slop delivery report: PASS or FAIL with evidence for claims without a source, fabricated content, decisions without a reason, anything delivered without being run, UI strings and comments.
- [ ] **Step 4:** append deferred items to `docs/plans/ui-redesign-backlog.md`; `mem_save` a short note.
- [ ] **Step 5: Commit** any doc change.

---

## Self-review

- **Spec coverage:** U1 Task 2; U2 Task 3; U3 and U4 and U6 Task 4; U5, U7, U10 Task 5; U8 Task 6; U9 Tasks 4 to 6 (inline overrides on touched elements) plus Task 1 (titles); the global page-title decision Task 1.
- **Placeholders:** none; where a test depends on existing mocking style the step says to read the file first.
- **Type consistency:** `pageTitle` is the only new variant name; `RecentSubmissionsList` props are used as defined in the Home plan; `hrefFor` builds the same `?q=&open=` URL as Home.
