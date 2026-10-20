# Settings page: audit and redesign (spec)

Date: 2026-10-19. Branch: `design/settings-page`. Status: approved (user, 2026-10-19); amended the same day with the panel redesign below.

## Why

1. Design audit of `/settings` (findings S1-S13), the next page in the redesign loop (theme foundation, Home, Submit, Submissions, Investigation, Dashboard, Campaigns done; Profile, Login, About after).
2. User, 2026-10-19: "go with recommendations", after researching official documentation and the most-starred open-source projects.

## What is true today (verified in code and captures)

- `pages/SettingsPage.tsx`: Admin/CERT only (`IsAdminOrCERT` on every settings view). Nine sections in one flat list (`features/settings/components/sections.tsx`); the active section is `useState("domains_allow")`.
- Panels: `EditableListPanel` (4 lists + `DomainPairPanel` with read-only Watcher lists), `CisoUsersPanel` (read-only), `FeederPanel` (switch), `ScoringTable` (26 analyzers; replaced the old card-based `ScoringPanel`), `ConnectorsPanel` (list + detail).
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

## Amendment: full panel redesign and connector logos (user, 2026-10-19)

User: "for each panel in settings redo the full design, especially connectors which are really difficult to read; learn from the best official web apps; and use the logo of each app instead of icons in connectors."

### Research (official design systems and open-source code)

- **IBM Carbon, status indicators** (carbondesignsystem.com/patterns/status-indicator-pattern): status is icon + shape + word, never colour alone; marks at 3:1; left-aligned beside the label; a consolidated status takes the highest-attention colour; plain text when nothing needs action.
- **IBM Carbon, forms** (carbondesignsystem.com/patterns/forms-pattern): top-aligned labels, one column, section headings, field widths matched to content, short visible helper text (essential information never in tooltips), validation on blur with specific errors, no disabled Save on long forms, primary action at the bottom and left-aligned, side panel or page above 5 inputs, progressive disclosure for optional fields.
- **GOV.UK summary list and question pages**: key/value rows with row actions whose hidden text names the key; one-sentence hints; "(optional)" on the minority of fields, no asterisks; fieldset + legend for related inputs.
- **Grafana data source docs** (grafana.com/docs/plugins/.../configure): Name, then Connection, then Authentication, then "Save & test"; a stored token is not returned to the browser.
- **Shopify Polaris app settings layout** (search summary only; the page itself redirected): description on the left, settings grouped into cards on the right.
- Not found online: citable teardowns of Linear, Vercel, Stripe or PostHog; nothing here claims anything about them.

### What is hard to read today (connectors)

One ungrouped run of 9+ fields (ai_narration mixes Ollama, OpenAI, Anthropic and Gemini keys); facts the API already returns but the page hides: `last_health_at` and `last_health_detail`, `events`, `schedules`, `docs_url`, `author`, and whether each secret is set (the config API returns `********` for a set secret); status and health as separate chips plus a dot; deliveries as a bare list.

### Design

**Shared panel pattern** (`PanelSection` and friends): every panel is title (h2) + one-line purpose + optional toolbar + content + optional sticky bottom action bar; key/value lists use `FactList` (a description list: key, value, optional action with hidden text); statuses use `StatusLabel` (icon + word, palette colours through `ensureContrast`, marks 3:1, left-aligned before the label).

**Connectors (master-detail):**
- List: rows grouped by category; row = logo tile, name, one-line cleaned description, `StatusLabel` (Connected, Incomplete, Disabled; Unhealthy when `last_health_ok === false`), enable switch at the row end (instant save).
- Detail header: logo tile, name, version, `StatusLabel`, "Last checked <relative time>: <health detail>" (hidden when `last_health_at` is null: "Not checked yet").
- Tabs (MUI Tabs with proper roles; the active tab is in the URL hash or query so it survives a refresh): **Overview** (`FactList`: Status, Health, Events, Schedules as "every 15 min", Author, Version, Documentation link), **Configuration**, **Deliveries**.
- Configuration: fields grouped by key prefix: a group is the leading token of the key (`ollama_url`, `ollama_model` -> "Ollama") when at least two fields share it, else "General"; group = fieldset + legend (h4 heading style), required fields first, optional ones inside a "Show optional settings" disclosure (hidden count in the label); a secret shows "Set" or "Not set" (from `********`) beside the field; helper text one short sentence plus the raw key; a sticky bottom bar (Save changes, Test connection) that is never disabled without a stated reason; the test result is a block under the bar saying what was tested (saved configuration).
- Deliveries: a table (Event, Case link, Status word, Time, Error), `Failed only` toggle, 10 rows with a "Showing the last 10" note; empty and error states.
- Phone: the list becomes a drill-in with Back (existing behaviour), tabs scroll horizontally.

**Logos** (frontend assets only, nothing fetched at runtime so air-gapped installs work): bundled in `src/features/settings/logos/` with `logos.ts` mapping connector name -> `{ src, brand, source }` and `LOGOS.md` recording the source URL, licence and retrieval date of every file. Sources: MISP `INSTALL/logos/misp-logo.svg` (MISP/MISP, AGPL-3.0), Chroma `docs/mintlify/images/favicon.svg` (chroma-core/chroma, Apache-2.0), Elasticsearch from Simple Icons (CC0 icon data; the mark remains the owner's trademark) for `case_search`, TheHive `images/thehive-logo.png` (TheHive-Project/TheHive, AGPL-3.0, archived), Watcher `Watcher/frontend/static/img/round-logo-fav.png` or the 196 px favicon (thalesgroup-cert/Watcher, AGPL-3.0). `smtp_notify` and `ai_narration` have no single brand, so they keep a neutral MUI icon in the same tile. PNGs are resized to 128 px and optimised (each file at most 20 kB); SVGs are cleaned (no scripts, no external references, `viewBox` kept). Logos render in a fixed-size tile with a neutral surface (`background.paper`) and a 1 px divider border so any logo stays legible in every theme; decorative (`alt=""`) because the name is always beside it; nothing is recoloured. A missing or failing logo falls back to the neutral icon tile. Brand marks are used only to identify the integration; this is recorded in `LOGOS.md`, and the user is asked to confirm brand usage for the final merge.

**Lists** (domains allow/deny, campaign domains, files, filetypes): purpose line from the section meta; toolbar (search, Add, Import file) and a count; rows = value, added date (`created_at` when present), Delete; empty state that says what the list does and how to add; Watcher synced lists as a separate, clearly read-only block ("Synced from Watcher, read-only").

**CISO users:** a table on desktop (User, Function, Scope, GBU, Country, Region) and cards on phone; search stays; "No scope" is text, not only colour.

**Email feeder:** one status card (`StatusLabel` for the state and the health badge, "Last checked" when the health query carries a timestamp, a paragraph on what the feeder does); the switch keeps the confirm.

**Scoring:** the table stays; each row gains a neutral share bar (decorative, `aria-hidden`, the percentage is the text).

### Tasks affected

Plan tasks 5-8 (panel pattern + logos, connectors, lists + CISO, feeder + scoring polish) are inserted before polish; the old Task 5 is now Task 9.

## Amendment 2: connector gallery with a configuration drawer (user, 2026-10-20)

User: the Task 6 connectors page "is still not good and too bulky"; inspire from the Watcher connectors page (blocks with modals), research official materials, "something gorgeous"; then "go with recommendations" and "for AI summary a short configuration with a switch on the provider instead of a long list of inputs".

### Research

- **Watcher** (thalesgroup-cert/Watcher, `frontend/src/components/Connectors/Dashboard.js`): KPI cards (Total, Configured, Incomplete, Disabled); search + status/health/category filters and a "group by category" toggle; one card per connector (72 px logo, name, version, status + health badges, inline test result that clears after 10 s, footer Edit / Test); a large edit modal (label, "sensitive" and "Manually set / From .env" tags, reveal eye, reset-to-default, raw key, Save disabled until dirty).
- **IBM Carbon, tile** (carbondesignsystem.com/components/tile/usage): a base tile may hold buttons in its footer; a clickable tile must not hold nested controls; tiles are flat, no drop shadows; do not mix variants in one group.
- **IBM Carbon, modal** (carbondesignsystem.com/components/modal/usage): modals for short tasks; go up a size when the body scrolls too much, to a full page when the largest size is not enough; only the body scrolls, header and footer fixed; focus lands on the first input and is trapped; validate on blur, keep the modal open on errors. Carbon forms: more than 5 inputs belong in a side panel or page.
- **NN/g, modal vs nonmodal** (nngroup.com/articles/modal-nonmodal-dialog): modals for critical or short exchanges; long forms and decisions that need the content behind them are a poor fit.
- Material 3 cards: the page returned no content; not cited.

### Decisions (user: "go with recommendations")

1. Configure opens a **right-side drawer** (full screen below md), not a centred modal: ai_narration alone has 14 fields, Carbon sends more than 5 inputs to a side panel, NN/g reserves modals for short exchanges, and the drawer keeps the gallery visible.
2. A **filter bar with status chips and counts** replaces Watcher-style KPI cards (the status strip above already shows counts).
3. ai_narration gets a **provider switch** (below) instead of one long list.

### Design

**Gallery** (replaces the Task 6 master-detail list; the list + detail components are deleted, their tabs move into the drawer):
- Filter bar: search (name, category, description), status chips with live counts (All, Connected, Incomplete, Unhealthy, Disabled; a chip is a toggle button with `aria-pressed`, counts from the fetched connectors), "Group by category" toggle (off by default; when on, category headings are `h3`).
- Grid: CSS grid `repeat(auto-fill, minmax(280px, 1fr))` (about 3 to 4 columns at 1440, 1 on phone); skeleton tiles while loading; "No connectors match" empty state with a Clear filters button.
- Tile (a base tile: a flat card with a divider border, no drop shadow, small hover lift disabled under `prefers-reduced-motion`): `ConnectorLogo` (48 px) with a soft glow behind it from the connector's accent colour and a small status ring (the ring is decorative; the status is the `StatusLabel` word), name (h3-level label), category, two-line cleaned description, `StatusLabel` (state; plus "Unhealthy"), footer: enable switch ("Enable <name>", instant save), **Test** button (spinner while running), primary **Configure** button. The tile body is not a click target. The Test result is an inline `role="status"` block on the tile (icon + text, "Tested the saved configuration", dismissible, no auto-dismiss).
- Accent colours: a documented per-connector brand accent in `logos/logos.ts` (`accent`), used only for the glow behind the logo (a branding exception like the white logo surface; recorded in `LOGOS.md`); neutral/theme primary for connectors without a brand.

**Drawer** (`ConnectorDrawer`, MUI `Drawer anchor="right"`, 600 px on desktop, full screen below md; opened by `?connector=<name>` so deep links and refresh work; unknown name opens nothing; Esc, the close button and the backdrop ask the existing discard `ConfirmDialog` when a draft exists):
- Header: `ConnectorLogo`, name (h2 of the dialog), version, `StatusLabel`, "Last checked <relative>: <detail>".
- Tabs (existing Overview / Configuration / Deliveries with `?tab=`), footer `ActionBar` (Save changes, Test connection; after a successful save an inline "Saved. Run a test now?" action).
- Setup checklist for Incomplete connectors (top of Configuration): "N of M required settings missing" computed from the saved config (a required field is missing when its saved value is empty; a set secret counts as present), each item a button that focuses its field.

**ai_narration provider switch** (frontend presentation layer in `connectorPresentation.ts`, keyed by connector name; every other connector keeps the generic grouped form):
- Facts from the backend (`connectors/contrib/ai_narration/connector.py`, `select.py`): the automatic `case_finalised` path allows only `ollama` and `openai_compatible` (`AUTO_PROVIDERS`); an empty `narration_provider` means `ollama`; `openai`, `anthropic` and `gemini` keys are used only by manual runs (`manage.py test_ai_narration`).
- UI: a segmented control "Provider used when narration runs automatically" with two options, **Ollama** and **OpenAI-compatible**, bound to the `narration_provider` field (the raw input is hidden; the key stays in the helper text). Only the selected provider's fields are shown: Ollama (`ollama_url`, `ollama_model`) or OpenAI-compatible (`openai_compatible_base_url`, `openai_compatible_api_key`, `openai_compatible_model`). The non-selected provider's saved values are kept untouched (hidden, never cleared). An unset or unknown saved value shows the Ollama segment selected with the note "Not set: Ollama is used" (unknown value: "Unknown provider '<value>' is saved; pick one to replace it"). Below, a collapsed disclosure "Manual-run providers (OpenAI, Anthropic, Gemini)" with the note "These keys are used only by manual runs (manage.py test_ai_narration), not when a case is finalised." containing those six fields.
- The checklist and the unsaved-draft logic include the switch (changing the segment is a draft change).

### Tasks affected

Plan Task 10 (after Task 9) implements this amendment. The Task 6 list/detail components are removed; Task 9's connectors contrast results are re-checked in Task 10.

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
