# Dashboard page: audit, regional view and data fixes (spec)

Date: 2026-10-13. Branch: `design/dashboard-page`. Status: awaiting user review.

## Why

1. **Feature request (Australia):** analysts want to see how many reports originate from their area and what the outcomes were.
2. **Design audit** of `/dashboard` (findings D1-D6 below).
3. **Data bugs found while investigating** (B1-B3): the existing dashboard numbers are not reliable, so a regional view built on them would be wrong.

## What is true today (verified in code)

- Every reporter belongs to Django groups for their **country** (`AU`), **region** (`APAC`) and **GBU**, set from LDAP in `profiles/profiles_utils/ldap.py` (`REGION_DICT`). `profiles/profiles_utils/scope.py` already filters cases by reporter group (AND across names).
- `GET /api/dashboard/summary/` accepts `scope` but only echoes it; its own schema note says data is not scope-filtered. A CISO who picks a scope sees global numbers labelled with their scope.
- **B1:** `update_monthly_reporter_stats` (`dashboard/dash_utils/dashboard.py`) writes `total_reporters` only on first creation and never updates it afterwards, so it stays at its creation-time value (0 on the dev stack while five reporters exist).
- **B2:** the monthly tables are refreshed by a cron for the current month only, and snapshots can be up to 24 h old, so `danger_counts` can disagree with the live "Top reporters" panel (Failure 0 vs Failure 60 on the dev stack).
- **B3:** `Case.results` defaults to `Inconclusive`, so counting `results` for cases still in progress would report outcomes that do not exist yet.
- The page has no stable first paint: three of three captures that switched theme immediately after load hit React error #185; one default-theme capture overlapped two panels and ran off screen (D1).

## Decisions (user, 2026-10-13)

- Access: **every signed-in user sees their own country**, with a toggle to **Overall**. CISO scope and CERT/Admin keep the ability to pick any country or region.
- Period: a report counts in the month its **case was created**.
- Fix the backend numbers in this cycle.
- Recommendations accepted by default (user did not object): sparklines are inline SVG (no new dependency); drag/resize is desktop only, phones get a fixed stacked order.

## Design

### Backend

One live aggregation replaces the stale tables for the summary:

`dashboard/dash_utils/regional.py::summarise(month, year, group_names|None) -> dict`

- Base queryset: cases created in the month, reporter in **all** `group_names` (None = Overall), reusing the AND semantics of `scope.py`.
- `reports`: count of cases created in the period.
- `outcomes`: counts for Safe, Inconclusive, Suspicious, Dangerous, Failure over cases with status DONE only; `in_progress`: count of the others. Percentages computed in the UI from these counts.
- `by_type`: counts per observable type (MAIL, FILE, URL, IP, HASH, IOC).
- `reporters`: number of distinct reporters; `new_users`: users joined in the period within the scope.
- `previous`: `reports` and outcome counts for the preceding month (one extra call to the same function, not six).
- `trend`: reports per ISO week inside the month.
- `top_reporters`: only for elevated users (CERT/Admin/CISO); other users get `null`, never names.
- Cached 120 s per (month, year, scope). The materialised snapshot keeps working for Overall by calling the same function. The monthly stats tables stay (other consumers) but the summary no longer reads them; B1 is also fixed in place (`total_reporters` refreshed on update) with a test.

Endpoint: `GET /api/dashboard/summary/?month&year&scope=<ALL|COUNTRY:AU|REGION:APAC|...>` keeps its path. Scope resolution is server-side and authoritative:

- plain user: `OWN_COUNTRY` (their `UserProfile.country`) or `ALL`;
- CISO: their CISOProfile scope, or `ALL`;
- CERT/Admin: any scope.
Requesting a scope outside the role returns 403. A user with no country gets `ALL` only, and the UI says why.

`GET /api/dashboard/scopes/` returns the choices the caller may use (countries present in profiles, regions, Overall, "My country").

### Frontend (`suspicious-ui`)

- Scope picker visible in the page header (not behind a gear): "My country (Australia) | Overall | <more for elevated>", plus month/year. Subtitle always reads "October 2026 · Australia".
- KPI row: Reports (with "vs September: +12"), Dangerous, Reporters, each with a hand-drawn SVG sparkline of the weekly trend; no giant arrows. Cards size to their content so nothing clips on a phone.
- Outcomes panel: stacked bar with a text count and percentage per outcome; "in progress" shown separately and labelled; Failure gets a neutral marker (no longer the same red as Dangerous).
- "What was reported" panel from `by_type`.
- Top reporters panel only for elevated users, as today.
- Drag and resize remain on desktop (`pointer: fine`); "Reset layout" becomes a real button shown only when the layout differs from the default; phones render a fixed stacked layout and never read or write saved layouts.
- Stable first paint (D1): reproduce first (theme switch during load, saved layout, sidebar width change), then fix the cause: save layouts only on user drag/resize, measure after the shell settles. A regression test must reproduce the crash on the old code.
- Cleanup (D6): remove duplicate "Overview" heading, inline weights above 700, dead state, make Retry a real button, use theme tokens.

## Global constraints

- Honest numbers only: no figure is shown that the backend did not compute for the displayed scope; an empty period says so.
- No names of reporters for non-elevated users, in the payload or the UI.
- Conventional Commits; nothing pushed; `deployment/compose_apps.yaml` never staged.
- Reuse existing building blocks (`EmptyState`, `ensureContrast`, `useResultHex`, theme typography); every colour passes the contrast helper in all 17 themes.
- Existing dashboard tests stay green or are adapted with a stated reason.

## Review focus (inputs most likely to bite)

1. User with no country/profile: must see Overall only, with an explanation, never an empty or error page.
2. Country with zero reports in the month: explicit empty state, no division by zero, previous-month delta shown as "no data" not "+0%".
3. Cases created near a month boundary and timezone (creation_date is timezone-aware): month bucket must match the Submissions list.
4. A plain user requesting another country's scope by hand-editing the query: 403, never data.
5. Reporter belonging to several countries/regions: AND semantics must not double count; `distinct()`.

## Tasks (to be detailed in the plan)

1. Backend: `summarise()` + scope resolution + endpoint + `scopes` endpoint + B1 fix, with tests (incl. review-focus 1-5).
2. Frontend foundation: header with scope picker, API types, stable first paint (D1) with a regression test.
3. KPI row, outcomes panel, by-type panel, sparklines; phone layout.
4. Layout customisation (desktop only), cleanup (D6), a11y, contrast across themes, final verification, backlog.
