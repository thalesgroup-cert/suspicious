# Dashboard Regional View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give every analyst a correct dashboard for their own country (or Overall), with outcomes of reports, and redesign the page; fix the backend numbers it rests on.

**Architecture:** One live aggregation (`dashboard/dash_utils/regional.py::summarise`) over `Case` filtered by reporter group, resolved server-side per role, replaces the stale monthly tables for the summary endpoint. The UI gets a header scope picker, KPI cards with SVG sparklines, an outcomes panel and a by-type panel; drag/resize stays desktop-only.

**Tech Stack:** Django/DRF + APITestCase (backend, `Suspicious/Suspicious/`), React 19, MUI 9, TanStack Query, Vitest browser mode (frontend, `suspicious-ui/`).

**Spec:** `docs/plans/2026-10-13-dashboard-page-design.md` (binding; this plan argues from it).

## Global Constraints

- Honest numbers only: nothing shown that the backend did not compute for the displayed scope; empty period says so; delta vs previous month shows "no data" when the previous month has no cases.
- Reporter names only for CERT/Admin/CISO, in payload and UI; plain users get `top_reporters: null`.
- Scope resolution is server-side: a scope outside the caller's role returns 403 (never data).
- Outcomes count cases with status DONE or CHALLENGED (a verdict exists); `in_progress` counts TODO and ON GOING. (Ruling: CHALLENGED cases keep their verdict.)
- Month bucket = `creation_date` in the server timezone, same as the Submissions list.
- Conventional Commits, trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; nothing pushed; never stage `deployment/compose_apps.yaml`; do not run `git stash`.
- Frontend: reuse `EmptyState`, `ensureContrast`/`readableOnTint`, `useResultHex`, theme typography (`pageTitle`, `subtitle2`); no inline `fontWeight` > 700 or `letterSpacing`; text never below theme caption size; `npx tsc -b`, `npx eslint .` (0 errors), `npx vitest run` green; e2e submit + ioc-road 7/7 (`e2e/investigation.spec.ts` keeps main's 2 known failures only).
- Backend: `docker compose --env-file .env run --rm --no-deps suspicious python manage.py test dashboard api` (from `deployment/`) green; add tests with the code.
- Node 22: `export PATH=$CLAUDE_JOB_DIR/tmp/node-v22.13.1-linux-x64/bin:$PATH`; pnpm only via `npx pnpm@11.1.3`.

## Review Focus

1. User with no country/profile: sees Overall only with an explanation; never an empty or error page.
2. Country with zero reports in the month: explicit empty state, no division by zero, delta "no data".
3. Cases near a month boundary: bucket matches the Submissions list.
4. Plain user hand-editing `scope` to another country: 403.
5. Reporter in several countries/regions: AND semantics, no double counting (`distinct()`).

## File Structure

- Create `Suspicious/Suspicious/dashboard/dash_utils/regional.py` (aggregation), `Suspicious/Suspicious/api/permissions/dashboard_scope.py` (scope resolution), tests `Suspicious/Suspicious/dashboard/tests_regional.py` and `Suspicious/Suspicious/api/tests/test_dashboard_scope.py`.
- Modify `api/views/dashboard.py` (`DashboardSummaryView`, new `DashboardScopesView`), `api/urls.py`, `api/serializers/dashboard.py`, `dashboard/snapshot.py` (use `summarise` for Overall), `dashboard/dash_utils/dashboard.py` (B1), `dashboard/README.md`.
- Frontend: modify `src/features/dashboard/api.ts`, `src/pages/DashboardPage.tsx` (591 lines: split the grid shell and layout storage into `src/features/dashboard/layout.ts`), `OverviewHeader.tsx`, `KpiTrendPanels.tsx`, `ThreatDistributionPanel.tsx`, `TopPrefixesPanel.tsx`; create `ScopePicker.tsx`, `Sparkline.tsx`, `OutcomesPanel.tsx`, `ByTypePanel.tsx` under `features/dashboard/components/`; tests next to them and `pages/__tests__/DashboardPage.test.tsx`.

---

### Task 1: Backend: live regional summary, scope resolution, endpoints, B1

**Files:** as listed under File Structure (backend).

**Interfaces:**
- Produces `summarise(month: int, year: int, group_names: list[str] | None) -> dict` with keys `reports:int`, `outcomes:{safe,inconclusive,suspicious,dangerous,failure:int}`, `in_progress:int`, `by_type:{MAIL,FILE,URL,IP,HASH,IOC,UNKNOWN:int}`, `reporters:int`, `new_users:int`, `previous:{reports:int, outcomes:{...}}`, `trend:[{week_start:"YYYY-MM-DD", reports:int}]`, `top_reporters: list[{label,value}] | None` (caller passes `include_names`).
- Produces `resolve_scope(user, requested: str|None) -> Scope(label:str, groups:list[str]|None)` raising `PermissionDenied`; scope strings: `ALL`, `OWN_COUNTRY`, `COUNTRY:<CC>`, `REGION:<NAME>`.
- Endpoint `GET /api/dashboard/summary/?month&year&scope` returns `{month, year, scope:{key,label}, ...summarise fields}`; `GET /api/dashboard/scopes/` returns `{default: key, options:[{key,label}]}` limited to what the caller may use.
- Consumes `profiles.profiles_utils.scope` AND semantics (`reporter__groups__name`, chained filters, `distinct()`), `UserProfile.country`, `get_case_type` logic (by-type counts must use the same type vocabulary: query by `fileOrMail__file/mail`, `nonFileIocs__url/ip/hash`, `observable_group`).

- [ ] **Step 1: Write failing tests** (`tests_regional.py`, `test_dashboard_scope.py`): counts for a seeded AU/NZ/US set of cases across two months; outcomes only for DONE/CHALLENGED and `in_progress` for TODO/ON GOING (running case with default Inconclusive is NOT an outcome); previous-month block; by_type vocabulary incl. IOC and UNKNOWN; a reporter in `AU` and `APAC` counts once for scope `COUNTRY:AU` and for `REGION:APAC`; case created 2026-10-31 23:30 UTC and 2026-11-01 00:30 UTC bucket by server timezone like the Submissions list (assert against the same month filter the Submissions view uses); zero-report country returns zeros and empty `trend`; plain user: default `OWN_COUNTRY`, `ALL` allowed, `COUNTRY:NZ` -> 403 (Review Focus 4), no country/profile -> only `ALL`, `scopes` lists just it; CISO with scope "AU|Off GBU" resolves to those groups; CERT any scope; `top_reporters` is `None` for plain users and present for CERT/CISO; B1 regression: `update_monthly_reporter_stats` twice with a new case between runs updates `total_reporters`.
- [ ] **Step 2: Run, verify they fail** (`docker compose ... manage.py test dashboard api.tests.test_dashboard_scope`).
- [ ] **Step 3: Implement** `regional.py`, `dashboard_scope.py`, view changes, serializer (update `DashboardSummaryResponseSerializer` and the `scope` OpenApi description: remove "not scope-filtered" text), snapshot for Overall via `summarise(..., None)`, B1 (refresh `total_reporters` in the update branch), README. Keep the old response keys the current UI reads (`kpis`, `danger_counts`, `top_prefixes`) populated from the new aggregation until Task 2 switches the UI, so the app keeps working between tasks.
- [ ] **Step 4: Run backend suite** (`manage.py test dashboard api`): green; paste the count.
- [ ] **Step 5: Commit** `feat(dashboard): live scoped summary with country/region scope and reporter-count fix`.

### Task 2: Frontend foundation: API, scope picker, stable first paint

**Files:** `features/dashboard/api.ts`, `ScopePicker.tsx`, `OverviewHeader.tsx`, `DashboardPage.tsx`, `layout.ts`, tests.

**Interfaces:** consumes Task 1 endpoints. Produces `getDashboardScopes()`, `getDashboardSummary({month,year,scope})` returning the new typed `DashboardSummary` (normalised, numbers default 0; `top_reporters` nullable); `ScopePicker({options, value, onChange})`; `layout.ts` exports `DEFAULT_LAYOUTS`, `loadLayouts(key)`, `saveLayouts(key, layouts)`.

- [ ] **Step 1: Reproduce D1 first.** Script under `$CLAUDE_JOB_DIR/tmp` (login once, reuse storage state; open `/dashboard` at 1440, dispatch `suspicious:theme-hydrate` immediately after `networkidle`, listen to `pageerror`) and record whether React #185 occurs and under which condition (theme during load, saved layout in localStorage, sidebar width change). Write the cause in the task report before fixing. If not reproducible after 10 runs, say so, and still harden: save layouts only from user drag/resize (`onDragStop`/`onResizeStop`) instead of `onLayoutChange`, and ignore `onLayoutChange` during mount.
- [ ] **Step 2: Failing tests:** header shows the scope picker and the subtitle "October 2026 · Australia" without opening any popover; picker lists only `scopes.options`; changing scope refetches with that key; plain user without country sees "Overall" only plus the line explaining that no country is set on the profile; month/year selectors work for everyone; a regression test for D1 that fails on the old code (e.g. layouts must not be written on mount or on theme change: assert `localStorage.setItem` is not called for `dashboard:layouts:*` without a drag).
- [ ] **Step 3: Implement.** Picker visible in the header (not behind a gear); Retry becomes a real `Button`; remove dead `openKpiTrends`/`selectedMetric` state and `void` hacks; `layout.ts` extraction; `useQuery` for history is dropped in favour of the summary's `previous`/`trend` (one request, not six).
- [ ] **Step 4: Gates** (vitest all, `tsc -b`, eslint) and a capture at 1440/390 light + midnight; commit `feat(ui): dashboard scope picker, typed summary and stable first paint`.

### Task 3: KPI row, outcomes panel, by-type panel, phone layout

**Files:** `KpiTrendPanels.tsx`, `Sparkline.tsx`, `OutcomesPanel.tsx`, `ByTypePanel.tsx`, `ThreatDistributionPanel.tsx` (replaced by `OutcomesPanel`; delete if unused), `TopPrefixesPanel.tsx` (reporters only for `top_reporters` non-null), `DashboardPage.tsx`, tests.

**Interfaces:** consumes the summary shape from Task 2. `Sparkline({values:number[], label:string})` is inline SVG, `role="img"` with an `aria-label` stating first and last value, `currentColor`, no animation when reduced motion.

- [ ] **Step 1: Failing tests:** KPI cards: Reports with "vs September: +12" and the previous value; "no data" delta when `previous.reports` is 0; Dangerous count; Reporters; each card has a Sparkline with a meaningful `aria-label`; OutcomesPanel: five outcomes with counts and percentages summing to 100% of finished cases, a separate "In progress (n)" line, Failure uses a neutral marker (not the Dangerous colour; assert by token), zero-report period shows `EmptyState` "No reports in this period" with the scope and month; ByTypePanel lists types with counts and omits zeros; `top_reporters: null` hides the panel and no reporter label appears in the DOM; phone viewport (matchMedia stub like `SubmissionsPage.test.tsx`) renders a single column with no `.react-resizable-handle` and no drag handle.
- [ ] **Step 2: Implement** with theme tokens and `ensureContrast`; cards size to content (no fixed row heights on phone: stacked `Stack`, grid only on desktop `pointer: fine`); drop the 60-100px arrows.
- [ ] **Step 3: Visual verification** on the rebuilt image (`docker compose --env-file .env build suspicious_ui && ... up -d suspicious_ui`): login once and reuse storage state; 1440 and 390 in light, midnight, paper, high_contrast, cyber with a country that has data (AU users: create two AU reporters and a few cases through `manage.py shell` for the capture only, in the dev stack, and remove them afterwards), and an empty country; VIEW every capture; `scrollWidth <= innerWidth` at 390.
- [ ] **Step 4: Gates; commit** `feat(ui): dashboard KPI cards, outcomes and by-type panels`.

### Task 4: Layout customisation, cleanup, a11y, contrast, final verification

- [ ] **Step 1: Failing tests:** drag/resize only when `(pointer: fine)` and viewport >= `md`; "Reset layout" is a real `<button>` rendered only when saved layouts differ from default and restores default; phone never reads or writes `dashboard:layouts:*`; heading outline `h1` Dashboard then `h2` per panel (remove the in-page "Overview" duplicate); every panel is a named region; scope picker and month/year keyboard operable; Retry is a button.
- [ ] **Step 2: Implement**; remove inline weights > 700; colours through helpers.
- [ ] **Step 3: Contrast sweep** like the Investigation Task 5 (Playwright, 7 themes incl. metal and future, Overview at 1440 and 390): fix dashboard-owned failures, list shared ones in the report.
- [ ] **Step 4: Final verification:** full vitest, `tsc -b`, eslint, backend suite, e2e 7/7, `investigation.spec.ts` vs main's 2 failures, final captures viewed, anti-slop delivery report (claims with a source, no fabricated content, decisions with a one-line reason, everything run, strings and comments), backlog append, commit `fix(ui): dashboard layout reset, accessibility and contrast`.

## Self-review

- Spec coverage: B1 Task 1; B2 live aggregation Task 1; B3 outcomes/in-progress Task 1; D1 Task 2; D2 KPI Task 3; D3 consistency via one aggregation Task 1; D4 phone Task 3; D5 visible scope Task 2; D6 Tasks 2 and 4; access model Task 1; regional feature Tasks 1-3.
- Placeholders: none; each test list names the exact assertions.
- Type consistency: scope keys (`ALL`, `OWN_COUNTRY`, `COUNTRY:<CC>`, `REGION:<NAME>`), `summarise` keys and `top_reporters` nullable are the same in Tasks 1-3.
