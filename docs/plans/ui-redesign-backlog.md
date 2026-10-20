# UI redesign backlog (after the design audit)

Run these after the design audit and redesign cycles are done. Each item is a discussion topic first, not a commitment.

## Relevance review
Which parts of the UI no longer fit after the recent backend changes (IOC road, trust hierarchy, derived observables, verdict explanation, threat badge, SOAR ticket output, Markdown report, connectors framework, ES case search)?
- Pages, tabs, panels, settings and help/tour (react-joyride) steps that are obsolete or redundant.
- Copy and docs screenshots that describe the old flows (e.g. the merged Indicators submit flow).
- Dead or orphaned components in `suspicious-ui/src/features/*` and `shared/components`.

## Pages to modify
- Pages whose data model changed: Investigation (verdict explanation, analysis health, sources), Dashboard (KPIs), Campaigns (campaign-detection connector). Settings (scoring table, connectors, lists) was redone in the Settings page cycle below.

## Pages to create (candidates, to be validated)
- Connector circuit-breaker view. The Settings connectors panel now shows status labels and the last 10 deliveries per connector (Settings page cycle); breaker state is still not shown anywhere in the UI.
- Analyzer health / failed-analyses overview.
- Search page backed by Elasticsearch case search.
- Allow-list management for IPs. Domains, campaign domains, file hashes and file types are managed in Settings; the backend has no IP list.

## Process
Use `ways-of-working:start-task` per item; discuss with the user before building anything.

## From theme review
Group A (midnight, graphite, slate, light, paper, renee). Each needs a change outside `themes.ts`.
- Card titles in `DashboardCard` are `Typography` body1 with `sx` weight, not a heading variant, so renee's serif-heading rule (h1 to h5) misses them. Home and dashboard. Fix: give the title a heading variant, or accept it.

Group B (high_contrast, cyber, metal, future). Each needs a change outside `themes.ts`.
- `AppLayout.tsx` line 165 paints a 7% primary radial glow behind every page; on high_contrast it shows as a brown wash top-left (alpha fill, spec 3 forbids). All pages. Fix: skip it when `effects.isAccessibilityTheme`.
- `features/dashboard/components/SoftCard.tsx` line 68 sets `alpha(divider, 0.28)` as the card border, so dashboard cards drop each theme's own card border (high_contrast's 2px solid + yellow top, cyber's cyan edge). Dashboard. Fix: same treatment the shared SoftCard got in 6x.
- Status and verdict chips (DONE, SAFE) use the fixed `colorStore` greens with an alpha fill, not the theme's `success` colour; on high_contrast they pass 7:1 (7.85) but keep an alpha fill. Home, submissions.
- Theme `MuiChip.root` colour overrides (cyber, metal, future, high_contrast) beat `color="warning"`, so `FeederHealthBadge` "Stale" renders in the theme accent, not amber. Home.

Group C (sunrise, valentine, the_one, winter, spring, summer, autumn).
- Primary-filled pills (table ID chips "232") keep white text on orange in summer, autumn and sunrise (about 3:1); `mkLight`/`mkDark` take `primary` as a bare colour, so a theme cannot set `primary.contrastText`. Home, submissions. Fix: let the helpers accept a contrastText, or set it in those three themes.
- Worst case of the `MuiChip.root` colour item above: sunrise `FeederHealthBadge` "Stale" is coral `#C4200F` on the amber warning fill, 1.85:1. Home.
- `THEME_CAPABILITIES.valentine.isDark` is `true` but the theme is built with `mkLight` (light palette). Fix: set it to `false` in `ThemeStore.tsx`.
- In themes.ts but over this group's 8-fix cap: summer `warning` `#D97706` gives MUI's white contrastText at 3.19:1 on the filled "Feeder: Stale" chip. Home. Fix: a darker warning such as `#B45309`.

## From the Home page cycle
- Mobile app bar title in `AppLayout` uses fontWeight 850 and letterSpacing -0.02em; check it when the layout is next reviewed.
- After the per-variant typography merge, page titles in paper, renee, high_contrast, sunrise and spring dropped to base sizes (h4 16px). Settings and Home were captured; Profile, About, Campaigns, Investigation and NotFound were not. Check them in the page audits.
- `themes.test.ts` pins exact heading sizes for paper only; the other themes are covered by a 40px cap.
- Donut centre counts verdict buckets while the share card counts monthly submissions; the dev stats snapshot has totals without buckets. Decide whether the stats job should fill the buckets.
- CERT and CISO users no longer have an "Open investigation" shortcut in the Threat card; the sidebar and the spotlight button cover it.

## From the Submit page cycle

- S8 page-title scale decision (global): page titles use the base h4 (16px) while panel titles are h5 (14px); side-card titles are subtitle1.
- Scheme-less URLs such as "evil.example/login.php" are classified as unrecognised on both client and server (the domain regex rejects "/"). Consider classifying host/path as a URL on both sides.
- The `file-invalid-type` branch in `onDropRejected` is unreachable (no `accept` is set).
- IPv6 zone ids are skipped by the UI but accepted by the server.
- The mode ToggleButtonGroup stays horizontal when stacked on phones.
- Duplicate `:not(:first-of-type)` border rules in `features/submit/components/cards.tsx`.
- e2e: login.spec (4 failures) and investigation.spec (2 failures) fail on main independently of the Submit work.
- A stray "Request failed." snackbar appears in the submit e2e after navigating to /submissions (unmocked requests).

## From the Submissions page cycle

- Server-side paging: the fetch is page 1 with page_size 100 and filtering/paging happen client-side, so more than 100 matches are unreachable. Move filters and paging to the server.
- Move `RecentSubmissionsList` to `shared/components` (Home imports it from features/home and it now imports features/submissions/CalmStatusChip).
- Submissions drawer header uses the coloured StatusChip for DONE while the rows use the muted chip.
- Nav drawer has no visible Close and its hamburger is covered while open.
- Focus returns to BODY after a drawer opened by a link closes.
- Reset shows for a column-header sort while the Filters chip and Sort select do not reflect it.
- Phone list has no copy buttons or column sort.
- Investigation drawer header is tall on phones (284px).
- The matchMedia stub is never unstubbed in SubmissionsPage tests.
- A malformed `?open=abc` deep link makes closeDrawer reset the search to the URL's q.

## From the submission drawer cycle

- Tab switch resets the Analysis tab's expansion state (groups and rows): lift it to the drawer.
- `CopyIconButton` (13 call sites) fails silently when the clipboard is unavailable: report it with `useSnackbar`, as Copy link already does.
- `ProfilePage` and `DashboardPage` carry their own CISO/CERT checks that omit Admin: share one elevated helper.
- The Profile colour preview (`features/profile/SemanticChips.tsx:80`) shows the raw colour while lists now show the contrast-adjusted text colour.
- The Sources "Verdict" (`ci.classification`) and the header chip (`row.result`) can differ for challenged cases.
- The meta line "n tests" and the tab label "Analysis (n)" are different facts (#21 shows 1 test next to Analysis (3)): label them or unify.
- `BADGE_W` is duplicated between the drawer and other result chips.
- The Comments title (shared `CommentThread`) is a styled Typography, not a heading, so the Comments tab has only the h2.
- Status strings are not trimmed in `reportSucceeded` / `unfinishedLabel`.
- Clipboard test cleanup (`delete navigator.clipboard`) is not in a `finally`.
- `shared/lib/contrast.ts` mis-decodes `hsl()` / `color()` inputs; no caller passes them today.
- The Home list "before" screenshots for the chip contrast change were never taken.
- Theme `future`: rendered backgrounds are lighter than their CSS colours in places (found while measuring the drawer chip); after the sheet header tint fix the verdict chip reads 4.71:1, but other text on that theme may be affected: audit it in the Theme review.
- Investigation's drawer header lost the grey/white wash toward the top (the shared SheetHeader tint went from a 22% wash to a 4% text-colour tint): check it in the Investigation page audit.
- The header-tint unit test was written after the fix (no recorded RED run).

## Investigation page cycle (2026-10-13)

Shipped on `design/investigation-page`: case-sheet header, More menu, decision-first Overview, Analysis/Discussion/Raw tabs, list with collapsible filters, bottom pager and phone list, stale-details guard on case switch.

Deferred:
- `?q=` is re-applied from the URL on Close/Next because `urlSyncKey` combines `q` and `open` (only hand-typed URLs hit it): sync `q` separately.
- `Heading` lives in Submissions `AnalyzerGroups.tsx`; move to `shared/components/SheetSection.tsx` (duplicates `SectionTitle`). The two drawers still duplicate Panel, tab `sx`, meta line and prev/next focus effect. `short` in `investigation/utils.ts` has no production caller.
- Header count chip shows "…" on every page change, not just while a search loads.
- Refetch details when the selected row's status changes (header can say Done while Redo reads "still being analyzed").
- IOC-road override form shows the stored band score the Overview hides: product decision.
- `screenshot_url` for #18/#22 answers 404 (backend data/file mismatch): hide section on image error.
- Midnight contained primary buttons are 3.1:1 (theme change). 17 theme/shared-component contrast entries: `docs/plans/investigation-contrast-2026-10.tsv`.
- Analysis expansion resets on tab switch; first analyzer group and observable panel can name different "worst"; "Result" row shows raw category text ("1 hi"); cyber table sticks out of its card by 12px at 1440 (scrolls inside).

## Dashboard cycle (2026-10-13)

Shipped on `design/dashboard-page`: live country/region/Overall summary (analysts see their own country, CERT/Admin/CISO scope rules, reporter names only for elevated), scope picker, KPI cards with weekly sparkline, outcomes and by-type panels, stable first paint, desktop-only drag/resize, stacked phone layout; backend fixes: stuck `total_reporters`, stale monthly tables, profile `country/region/gbu` read-only, user-cases aggregate locked to CERT/Admin, query cache cleared on logout/login.

Accepted deviations from the spec: CHALLENGED cases count as finished; sparkline only on the Reports card; the D1 test guards the defects found (layout saved on width/theme change, first paint at 1280px) because React #185 never reproduced in 69 runs; contrast swept in 7 of 17 themes (`docs/plans/dashboard-contrast-2026-10.tsv`).

Deferred:
- Default month uses the browser clock, bucketing uses the server timezone: have `/scopes/` return the server's current month.
- Home still reads the cron-fed tables while the Dashboard is live, so the two can differ for the same month; Home scope counts ignore the new CISO group check (`api/views/home.py`, `scoped_case_queryset`).
- LDAP never removes old country groups, so a reporter who moves AU to FR counts in both.
- Weekly dangerous series and sparklines on the other KPI cards; country/region ranking for elevated users (replaces the dropped Groups toggle).
- The old Campaigns page threw React #185 on window resize (also on main, 2 of 4 runs each). That page was replaced by the Campaigns cycle below, which has no react-grid-layout; whether the crash is gone was not re-tested, it is only expected from the removed layout code.
- `materialise_dashboard_snapshots` still runs nightly (02:00) but nothing reads the snapshot: remove or wire a reader.
- Saved layout drops the reporters panel position when `top_reporters` is null; KPI cards leave ~40px empty space (fixed grid row height).
- Contrast in shared components: the Dashboard itself was swept in 7 of the 17 themes that existed then (the `lure` theme came later), the rest are not. The old Campaigns status chips (2.1 to 3.8:1) and metal's outlined labels (4.05:1) were measured on the replaced Campaigns page; the new page was swept in all 17 themes of the time (see the Campaigns cycle); the Settings cycle swept all 18, `lure` included.
- Minor backend: stored CISO scope "AU|AU" refuses the "AU" alias; service-mailbox exclusion depends on DB collation and on `SUSPICIOUS_EMAIL` being set; reporter labels differing only in case are not disambiguated.

## Campaigns page cycle (2026-10-19)

Shipped on `design/campaigns-page`: header and period selector, KPI strip with deltas, messages per day with campaign windows, classification mix, sortable campaigns table (cards on a phone), lazy 3D embedding map (category, campaign and age colours, date range, clouds, keyboard controls, 2D and table fallbacks), near-known-bad and novel review lists, `GET /api/campaigns/summary/` and `/neighbours/`. Contrast swept in 17 themes at 1440 and 390: `docs/plans/campaigns-contrast-2026-10.tsv` (failures, per-theme summaries and the 3D cloud rows; one row per check is in the sweep's full table, kept with the task reports). The resize crash noted under the Dashboard cycle was on the replaced grid layout; the new page has none of that code, but the crash was not re-tested there.

Deferred:
- Per-country scoping of campaigns needs reporter metadata (country, region) in the message store; today every figure is organisation-wide and the header says so.
- Live refresh (Refresh button only), and a campaign detail page (the table links to the latest case and selects the campaign's cases in the map).
- Chroma sample cache shared by the PCA and neighbours endpoints (each reads the same sample, about 30 MB per 1,500 messages).
- Header glow parity with `OverviewHeader`; the Mix card does not stretch to the height of the volume card.
- The empty state hides the map, which is not period-scoped and could still be shown.
- vite `manualChunks` size guard: nothing fails the build if three/R3F/drei ever land in `vendor` again (the 3D chunk is about 253 kB gzip).
- Map state (colour mode, filters, camera) is lost on the 2D/3D toggle.
- One cloud per category is a single mean and covariance: a multimodal category (a campaign plus background mail) gets one oversized ellipsoid. Per-cluster or per-campaign clouds would fix it.
- Weekly dangerous series and country/region ranking for elevated users (as on the Dashboard); first and last seen in the campaigns table are within the selected period, not over the campaign's life.
- `materialise_dashboard_snapshots` is still unread by this page too.
- Unclassified and Unwanted use two blue-greys that differ mainly in lightness (about 1.4:1 between them in light); both are always labelled, but a point-shape or pattern cue in the map would separate them.
- Contrast in shared components: the sidebar avatar initial is 2.7 to 4.35:1 in 8 themes (the Settings sweep sees it again, 2.8:1 or more in 5); themed hairline dividers are decorative gradients.
- Keyboard users reach only the first 200 messages in the point table (the cap keeps the DOM small): add a text filter or pagination.
- `embeddingMap3d.gl.test.tsx` skips silently where the browser has no WebGL 2; CI should assert that it ran.
- `mail-volume` still computes campaign bands that this page no longer reads (kept for old clients): keep them or stop computing them.
- drei brings about 45 transitive packages for `OrbitControls` and `PerformanceMonitor`; `three` with its own `OrbitControls` would be lighter.
- PCA is not cached, and neighbours is cached per exact `limit` (up to 5,000 distinct keys; about 30 MB per limit by the earlier estimate).
- Query bounds (case id limit, limit ranges) are written in both the serializers and the service: one source.
- Task 4 minors still open: the fog's initial `#000000` (overwritten from the theme before the first frame). The disabled point-table Select's reason is now reachable by keyboard and its colour is 4.5:1.
- Chroma reads: every paged scan now fails closed (summary, volume, counts, PCA and neighbours return their empty, uncached payload when a page read fails); a retry or a partial-result marker for the PCA sample was not built.

## Settings page cycle (2026-10-19)

Shipped on `design/settings-page`: sections as URLs (`/settings/<section>`, bare path redirects) with a grouped nav and a phone picker, a status strip built from fetched data, single-entry remove with Undo, confirmations (bulk delete, feeder off, discard) that state the consequence, honest batch counts (failed rows stay selected), an unsaved-changes guard, an analyzer scoring table (shares, sort, search, weight-sum guard in the UI and in `AnalyzerSettingsDetailView.patch`), a connectors master/detail with bundled logos, Overview, Configuration and Deliveries tabs and a sticky save bar, redone lists and CISO users, and a feeder status card. The only backend change is the weight-sum guard. Contrast swept in 18 themes at 1440 and 390: `docs/plans/settings-contrast-2026-10.tsv`.

Deferred:
- `campaign_domains_allow` semantics: besides skipping campaign detection it is also unioned into the deny-listed set at scoring (`case_score_calculation.py:94-110`), which can turn a newsletter domain into a Dangerous verdict. Product decision pending; the UI gives that list no purpose sentence until it is made.
- Allow-over-deny precedence is not stated anywhere in the UI copy.
- Per-list empty-state copy: every list says "No entries yet. Paste values above or import a file." and none says what the list does.
- The analyzer `tier` field (1 to 3) is accepted by `PATCH /settings/analyzers/<id>/` but cannot be edited in the UI.
- Feeder facts: Reason shows only when offline. When `feeder_status` is "degraded" the payload's `checks` (IMAP healthy/configured, MinIO ok) are not shown.
- Relative times ("Last poll", "Last checked") use the browser clock; a skewed client clock misstates them. The payload's `checked_at` could be the reference.
- Test connection tests the saved configuration only (the UI says so); an endpoint that accepts a draft would let users test before saving.
- The optional-settings disclosure resets when the tab changes, because the Configuration tab unmounts.
- The weight-sum guard race is closed with a transaction and `select_for_update`, but the tests are sequential: nothing exercises two concurrent PATCHes.
- Brand-logo usage needs the owner's confirmation before merge (`features/settings/logos/LOGOS.md`: Chroma favicon carries a Streamline marker, TheHive is cropped to its emblem, Elasticsearch is filled with the brand colour on a white tile).
- Connector `description` text is cleaned in the UI (`cleanDescription`); the manifests themselves should carry final copy.
- `InnerCard` in `features/settings/components/cards.tsx` still uses the literal `alpha("#fff", 0.025)` in dark mode.
- Shared `FeederHealthBadge`: the dot loses its tone under themes that override `MuiChip.root` colour (cyber, metal, future, high_contrast). Settings now uses `StatusLabel`; Home still uses the badge.
- Shared visually-hidden helper: eight local copies (Settings: ConnectorOverview, CisoUsersPanel, ConnectorDeliveries, FactList, SettingsNav, ScoringTable, plus the inline `:empty` rule in EditableListPanel; Campaigns: PointTable, EmbeddingMap3D). `@mui/utils` has one but is not a direct dependency.
- Profile has no unsaved-changes guard; `UnsavedProvider`, `useReportUnsaved` and `ConfirmDialog` from `features/settings` could be reused there.
- Contrast in shared components and theme definitions, listed in `settings-contrast-2026-10.tsv` and not changed: outlined field borders (MUI `notchedOutline` in `themes.ts`, 1.3 to 2.9:1 in 17 themes), switch thumb and track (MUI Switch palette, 1.0 to 2.9:1 in all 18 themes), input placeholders (MUI default opacity, 2.6 to 4.5:1 in 9 themes), the sidebar avatar initial (2.8 to 4.3:1 in 5 themes), and contained button labels where the theme's `contrastText` is under 4.5:1 on its fill (3.0 to 3.8:1 in 6 themes; `mkLight`/`mkDark` cannot set `primary.contrastText`, as noted under the Home cycle).
- The sweep does not cover snackbar variants, focus indicators, or hover states other than the bulk bar.


## Follow-ups raised during the Settings cycle (2026-10-20)
- Allow/deny list tables: `user` FK is CASCADE, so deleting a user deletes the entries they added with no `ListChangeLog` row. Change to `SET_NULL` (nullable `user`, check readers of `.user`) in its own migration, then log removals made by the cascade or keep the entries.
- Allow-list / campaign / MISP / scoring majority rule: approved design in `docs/plans/2026-10-20-allowlist-launch-misp-scoring-design.md`; implement on a new branch from main.
