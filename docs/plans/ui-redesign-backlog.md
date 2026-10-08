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
