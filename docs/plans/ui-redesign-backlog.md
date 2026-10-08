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
