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
- `SoftCard` (`features/home/components/SoftCard.tsx`, `shared/components/SoftCard.tsx`, `features/about/components/cards.tsx`) sets `border: alpha(theme.palette.divider, isDark ? 0.28 : 0.9)`. `alpha()` replaces the divider's alpha, so every light theme gets a 90% black card outline and every dark theme a 28% white one, which overrides each theme's `MuiCard` border (renee's gold hairline, paper's soft border). Shows on home and dashboard. Fix: use `edge(theme, …)` or drop the `sx` border.
- `SoftCard` paints a hardcoded white gradient (`#fff` 0.88 to `grey[50]`) on light themes, so paper and renee cards are white instead of `background.paper` (#FAF7F2, #FBF6EE) and lose paper's grain. Shows on home and dashboard. Fix: use `theme.palette.background.paper`.
- `AppLayout` sidebar background is a hardcoded white gradient on light themes (`layouts/AppLayout.tsx:160`), so the paper and renee sidebars are white on a cream page. All pages. Same file: `sidebarBorder` has the `alpha(divider, 0.9)` problem above.
- `AppLayout` root box paints `shellBg` (opaque `background.default`) over `body` (`layouts/AppLayout.tsx:338`), so every theme's `MuiCssBaseline` body texture never shows: paper grain, renee grain, slate grid, midnight glow. This is why midnight's "starfield specks" cannot be added from `themes.ts`. All pages.
- Card titles in `DashboardCard` are `Typography` body1 with `sx` weight, not a heading variant, so renee's serif-heading rule (h1 to h5) misses them. Home and dashboard. Fix: give the title a heading variant, or accept it.
