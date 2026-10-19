# Settings page: audit and redesign (spec)

Date: 2026-10-19. Branch: `design/settings-page`. Status: awaiting user review.

## Why

1. Design audit of `/settings` (findings S1-S13), the next page in the redesign loop (theme foundation, Home, Submit, Submissions, Investigation, Dashboard, Campaigns done; Profile, Login, About after).
2. User, 2026-10-19: "go with recommendations", after researching official documentation and the most-starred open-source projects.

## What is true today (verified in code and captures)

- `pages/SettingsPage.tsx`: Admin/CERT only (`IsAdminOrCERT` on every settings view). Nine sections in one flat list (`features/settings/components/sections.tsx`); the active section is `useState("domains_allow")`.
- Panels: `EditableListPanel` (4 lists + `DomainPairPanel` with read-only Watcher lists), `CisoUsersPanel` (read-only), `FeederPanel` (switch), `ScoringPanel` (26 analyzers), `ConnectorsPanel` (list + detail).
- Analyzer weights are relative shares: `score_process/scoring/processing.py:61-67` computes `sum(score * weight over non-failed reports) / sum(weight over all reports of the case)`; a total of zero raises `ValueError` ("cannot compute scores"). A failed analyzer lowers the score because its weight stays in the denominator.

## Findings

| # | Finding |
|---|---|
| S1 | Active section is local state: a refresh returns to "Domains allowlist"; no deep link, Back button does nothing. |
| S2 | Nine flat sections with long subtitles; on a phone the whole list sits above the content. |
| S3 | Header repeats itself (user avatar beside the title, "Admin console" card with the username, section title card with another Refresh); the page subtitle omits Connectors and CISO users. |
| S4 | "Refresh all" invalidates `["settings"]` only: connector queries (`["connectors"]`, `["connector-config", …]`, `["connector-deliveries", …]`) are missed. |
| S5 | No destructive action asks for confirmation (remove entry, bulk delete, feeder off). |
| S6 | Bulk delete and scoring "Save all" are sequential awaits with no error handling: a failure mid-loop aborts silently, the list is not refreshed, and "Save all" reports the planned count as saved. "Test connection" has no `onError`. |
| S7 | Scoring: 26 near-identical cards (about 5,100 px), no search, filter or sort. |
| S8 | Scoring colours weights red below 0.4 and green above 0.7 with literal hexes; weights are relative shares, so low is not bad, and every analyzer is red at the default 0.2. |
| S9 | Nothing says what a weight does. All weights at 0 makes every case fail to score (`ValueError`); the UI allows it. |
| S10 | Connector fields are labelled with raw keys (`ollama_url`); one description tells the reader to see an internal path (`docs/specs/…`); deliveries show a coloured dot and no status word, last 5 only. |
| S11 | Literal colours (`#22C55E`, `#F59E0B`, `#EF4444`) in the feeder and scoring panels; contrast of chips, disabled buttons and the feeder state to be swept over all themes. |
| S12 | Weight sliders have no accessible name; panel titles are `h6` directly under `h1`; no unsaved-changes guard when leaving the page. |
| S13 | Results of bulk actions go only to transient snackbars. |

## Research that shaped the design

- **Primer, "Saving" pattern** (primer.style/product/ui-patterns/saving): explicit saving is the default for forms and automatic saving only for imperative controls (toggles, segmented controls); do not mix the two in one form; keep the user's data when a save fails; warn with `beforeunload` when leaving with unsaved changes; confirm destructive actions, offer undo for risky ones; keep Save enabled; verb labels; github.com avoids toasts because of unresolved accessibility issues, so results that matter are shown inline.
- **GitHub settings redesign** (github.blog changelog 2022-02-02): Primer `NavigationList` groups similar settings pages into sections "for improved information architecture and discoverability"; each settings area has its own URL.
- **Immich** (github.com/immich-app/immich, about 117k stars; `web/src/lib/components/shared-components/settings`): settings grouped in titled accordions (`h2`, `aria-expanded`), a per-field "unsaved change" tag, one Save / Reset / "Reset to default" row per group, routes per admin area (`/admin/system-settings`, `/admin/users`, `/admin/server-status`).
- **WCAG 2.2 SC 3.3.4** (Error Prevention: legal, financial, data, AA): a submission that changes or deletes user-controllable data must be reversible, checked, or confirmed. SC 3.3.1: errors identified in text.
- **WAI-ARIA APG slider**: the slider takes an accessible name (`aria-labelledby` or `aria-label`); `aria-valuetext` when the number alone is not meaningful; arrows step, Home/End jump to the ends, PageUp/PageDown optional.
- **Secondary UX guidance** (saasui.design, uxcel: vendor blogs, not studies): 4 to 6 top-level groups, most-used first, destructive actions visually separated, confirmation matched to the stakes. Used only where it agrees with the primary sources above.

Not found online: an official Material 3 settings page pattern (the searches returned only third-party skill files). Nothing here depends on it.

## Decisions (user, 2026-10-19: "go with recommendations")

1. Deep-linkable sections: `/settings/:section`; no section opens the first.
2. Scoring shows each analyzer's share of the total weight (weight / sum of all weights in the list), labelled honestly: a case's score divides by the weights of the analyzers that ran on that case.
3. Scope: all six proposal points in one cycle.

## Design

### Navigation, header, status

- Route `settings/:section?` (keys unchanged: `domains_allow`, `domains_deny`, `campaign_domains_allow`, `emails_files_allow`, `filetypes_allow`, `ciso_users`, `email_feeder`, `scoring`, `connectors`); unknown section redirects to the first; Back/forward work; the active item carries `aria-current="page"`.
- Groups (labels as headings in the nav): **Detection lists** (Domains allowlist, Domains denylist, Campaign domains, Files allowlist, Filetypes allowlist), **Access** (CISO users), **Ingestion** (Email feeder), **Scoring** (Analyzer scoring), **Integrations** (Connectors). Subtitles move out of the nav items into the panel header (the nav is titles only).
- Phone: the nav becomes a labelled select-style picker at the top (a native-backed MUI `Select` or a horizontal scroller, decided in the plan from the existing nav patterns); desktop keeps the left rail, sticky.
- One header: "Settings" (h1) + subtitle that names all areas + one Refresh (invalidates settings, connectors, connector config and deliveries). Drop the avatar and the "Admin console" card.
- Status strip (facts the page already fetches, no new API): email feeder running/stopped (+ health badge), connectors enabled of total and how many report unhealthy, analyzers active of total. Each item links to its section. Each loads independently; a failed one says "unavailable", never a spinner forever.

### Safety

- `ConfirmDialog` (shared inside the feature): states the consequence and the count; used for remove entry (undo instead for a single entry, see below), bulk delete ("Delete N entries from <list>? This cannot be undone."), feeder off ("The feeder stops ingesting mail immediately; existing cases are unaffected."). Focus returns to the invoking control.
- Single entry removal: no dialog; the entry is removed and an "Undo" action re-adds the same value through the existing add endpoint (reversible, SC 3.3.4). If undo fails it says so.
- Bulk operations (`runBatch` helper, sequential to keep the server load as today): collect per-item results; summary "3 of 5 deleted, 2 failed" shown inline (`role="status"`) and as a snackbar; failed items stay selected and the list is refreshed either way. Scoring "Save all" uses the same helper and states real counts.
- Test connection: error handled (message with the HTTP detail when present).
- Unsaved changes: scoring drafts and connector config drafts mark the nav item with a dot and "unsaved" text (not colour alone), and a `beforeunload` guard plus a router blocker prompt on leaving. Save stays enabled (Primer) and reports "Nothing to save" when clean.
- Weights: when the sum of active analyzers' weights would be 0 the Save is refused with an inline error (SC 3.3.1) and the backend rejects it too (400) so the API cannot produce the `ValueError` state. The plan's Task 3 verifies where that guard belongs in `AnalyzerSettings…View`.

### Analyzer scoring

- A table (not cards): Analyzer (name + cortex id), Active, Weight (slider + number input, step 0.1, 0 to 1), Share of total (computed), state ("Modified" text + marker). Search by name, filter "Modified only", sort by name / weight / share. Rows virtual-free (26 rows).
- Explanation line under the title: "Weights are relative. A case's score is the weighted average of the analyzers that ran on it; changing one weight changes every analyzer's share." (copy checked in review).
- Neutral colour only (primary for the changed marker, text for numbers): no red/green. Sticky action bar when any change is pending: "N unsaved changes", Reset to saved, Save all.
- Accessibility: slider `aria-label="<analyzer> weight"`, `aria-valuetext="0.4, 12% of the total"`; Home/End/arrows (MUI default) plus the number input as the exact-entry path; table has a caption/name and sortable headers use `aria-sort`.

### Connectors, feeder, lists, CISO

- Connectors: field labels from the schema's human label when present, else a de-snaked title ("Ollama URL") with the raw key as helper text; internal doc paths stripped from descriptions in the UI only if the description is not itself link-safe (the plan decides between a regex strip and a backend copy fix; a backend description edit is acceptable if the connector owns it); deliveries show a status word beside the dot, the last 10, with a "view more" disabled-free note when the API caps; Save/Test disabled-state reasons stated.
- Feeder: palette tokens (`useResultColors`) in place of literals; switch has the confirm for turning off; state text "Running / Stopped" plus health.
- Lists: unchanged semantics; the "0 total" and empty states use the shared empty component; the Add button is explained when disabled ("Enter at least one value").
- CISO users: unchanged data (read-only); table-like grid becomes responsive cards already; heading levels fixed.
- Headings: h1 page, h2 per panel title, h3 sub-sections; unique region names.

### Theme and accessibility

- Every colour from the theme or result palette via `useResultColors` / `ensureContrast`; contrast sweep over all themes at 1440 and 390 (the campaigns sweep script is reused; table copied to `docs/plans/settings-contrast-2026-10.tsv`); shared failures are listed, not changed.
- `prefers-reduced-motion`: no transition animations beyond the existing theme defaults.

## Global constraints

- Frontend only except the weight-sum guard (backend, small, additive, tested). Admin/CERT access unchanged; no new endpoints; no data model change.
- Honest copy: no number shown that the page cannot compute from data it already has; the share column says what it is.
- Conventional Commits with trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; nothing pushed; never stage `deployment/compose_apps.yaml`; no `git stash`.
- Gates: `npx vitest run`, `npx tsc -b`, `npx eslint .` (0 errors), e2e submit + ioc-road 7/7, backend `ww test backend api dashboard` green. Host `node` is v18: put node 24 first on PATH (`$CLAUDE_JOB_DIR/tmp/bin`).

## Review focus

1. Navigation by URL: unknown section, trailing slash, browser Back, a non-Admin/CERT user (still the "Not authorized" state).
2. Bulk delete and Save all with one failing item: counts true, failed items kept selected, list refreshed, no unhandled rejection.
3. Weights all zero or the sum zero: refused in UI and API; a single analyzer at 0 is allowed; inactive analyzers handled as the backend does.
4. Unsaved changes: leaving the section, the route, closing the tab; Save with nothing to save.
5. Keyboard-only: nav, sliders, number inputs, confirm dialog focus trap and return, table sort; screen reader names; phone width; all themes; reduced motion.

## Tasks (to be detailed in the plan)

1. Foundation: route + grouped nav + header + status strip + `ConfirmDialog`, `runBatch`, unsaved guard; heading outline.
2. Lists and feeder safety: confirm/undo/bulk errors, feeder confirm and palette, CISO headings, empty states.
3. Scoring: table, search/filter/sort, shares, explanation, sticky bar, weight-sum guard (frontend + backend + tests).
4. Connectors: labels, deliveries, test connection errors, unsaved config guard, description copy.
5. Polish and verification: contrast sweep, captures in all themes, a11y tests, anti-slop report, backlog, contrast table.
