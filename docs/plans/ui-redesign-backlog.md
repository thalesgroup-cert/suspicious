# UI redesign backlog (after the design audit)

Run these after the design audit and redesign cycles are done. Each item is a discussion topic first, not a commitment.

## Relevance review
Which parts of the UI no longer fit after the recent backend changes (IOC road, trust hierarchy, derived observables, verdict explanation, threat badge, SOAR ticket output, Markdown report, connectors framework, ES case search)?
- Pages, tabs, panels, settings and help/tour (react-joyride) steps that are obsolete or redundant.
- Copy and docs screenshots that describe the old flows (e.g. the merged Indicators submit flow).
- Dead or orphaned components in `suspicious-ui/src/features/*` and `shared/components`.

## Pages to modify
- Pages whose data model changed: Investigation (verdict explanation, analysis health, sources), Dashboard (KPIs), Campaigns (campaign-detection connector), Settings (scoring panel, connectors, allow-lists).

## Pages to create (candidates, to be validated)
- Connectors status/delivery ledger and circuit-breaker view.
- Analyzer health / failed-analyses overview.
- Search page backed by Elasticsearch case search.
- Allow-list management (domains, IPs) if not covered in Settings.

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
- Submissions dropped the title avatar while Investigation and Settings keep theirs.
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
