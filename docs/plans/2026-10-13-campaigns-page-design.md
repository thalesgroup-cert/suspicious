# Campaigns page: audit and 3D embedding map (spec)

Date: 2026-10-13. Branch: `design/campaigns-page`. Status: awaiting user review.

## Why

1. **Request:** make the PCA scatter 3D so analysts can see the clouds of email categories.
2. **Design audit** of `/campaigns` (findings C1-C7).
3. The page is the next in the redesign loop (theme foundation, Home, Submit, Submissions, Investigation, Dashboard done).

## What is true today (verified in code and captures)

- Data comes from the ChromaDB message store, not from cases: organisation-wide, never scoped. Access `StatsReadPermission`: CISO, CERT, Admin, staff.
- `GET /api/campaigns/pca/?limit` runs a plain numpy SVD (`api/services/campaigns/service.py`), returns `x`, `y` only and `explained_variance` of length 2 (serializer enforces min=max=2). Sampling is deterministic, up to 5000 points.
- `classification-counts` folds SUSPICIOUS into UNWANTED (three buckets) while the PCA chips show four labels; the Dashboard uses Safe/Inconclusive/Suspicious/Dangerous.
- The 2D chart stretches its axes with a campaign `ReferenceArea` (`ifOverflow="extendDomain"`), so 31 points sitting near the origin are not visible. The grid renders about 110 px narrower than the page and clips the right of the PCA chart (same first-paint width defect fixed on the Dashboard). `onLayoutChange` saves layouts on every width change and React #185 on resize reproduced on `main` (2 of 4 runs).
- "Live" chip is decorative; chart colours are literals (#3B82F6, #EF4444, CLASS_COLORS); filter chips put white text on orange/cyan (about 2:1); one spinner waits for all three queries; error text mentions "API routes / permissions"; no empty state; no legend for the volume areas; campaign chips truncated; campaign windows are inferred from shared `sourceRefs` (a heuristic) but the page does not say so.

## Decisions (user, 2026-10-13: "go with recommendations")

- Keep CISO access; the page says "Organisation-wide" (per-country filtering needs reporter data in the store: not checked, backlog).
- Show four classifications as stored (Safe, Unwanted, Suspicious, Dangerous): the counts endpoint stops folding Suspicious into Unwanted.
- Drag/resize customisation is dropped on this page (see layout section); no shared layout extraction is needed for Campaigns.
- Add `three`, `@react-three/fiber` (v9 pairs with React 19) and `@react-three/drei` (OrbitControls only), loaded lazily; measure the bundle in Task 3 and fall back to plain `three` + its OrbitControls if the chunk is heavy.

## Research that shaped the design

- Embedding Projector (Smilkov et al., arXiv 1611.05469; Google blog): 3D readability relies on redundant depth cues (point size by distance, fog), natural rotate/zoom/pan, labels on demand, click a point to list nearest neighbours with distances and highlight them. Projections are an exploration aid, not proof.
- R3F "Scaling performance" (r3f.docs.pmnd.rs): `frameloop="demand"` with `invalidate()` for OrbitControls changes, `InstancedMesh` for many points in one draw call, adaptive pixel ratio while moving.
- three.js OrbitControls docs: `enableDamping`, `minDistance`/`maxDistance`, `listenToKeyEvents`, `touches`, `saveState()`/`reset()`, `change` event.
- Canvas content is invisible to assistive technology: expose structured text and equivalent controls outside the canvas (R3F a11y guidance, WCAG 1.1.1, 2.1.1, 1.4.11).

## Design

### Backend (small, additive)

- `get_pca`: use `vt[:3]`; points get `z`; `explained_variance` has up to 3 entries (serializer min 2, max 3, `z` optional default 0.0). Degenerate cases (1 point, 1 dimension, SVD with < 3 components) return `z = 0` and a 0 ratio. Old clients keep working.
- `classification-counts`: four keys `SAFE`, `UNWANTED`, `SUSPICIOUS`, `DANGEROUS` (no folding); docs updated.
- No change to access rules.

### 3D map (`features/campaigns/components/EmbeddingMap3D.tsx`, lazy)

- One `InstancedMesh` (sphere or sprite) for all points, colour per instance from the result palette (`useStatusColors` / result colours, text/marks through `ensureContrast` against the canvas background). `frameloop="demand"`, `invalidate` on controls `change`, adaptive pixel ratio while moving.
- Depth cues as in the Projector: point size and opacity by distance, scene fog; axes with labels "PC1 24%", "PC2 15%", "PC3 9%" (`explained_variance`), faint grid.
- Category clouds: per category a translucent ellipsoid at 2 sigma from that category's own points (mean + 3x3 covariance eigen decomposition via a small unit-tested Jacobi routine), drawn only when >= 5 non-degenerate points; chip toggles per category show/hide points and cloud together (`aria-pressed`).
- Interaction: OrbitControls (drag rotate, wheel/pinch zoom, right-drag pan, damping on, min/max distance from the data bounds), "Reset view" button (`reset()`), keyboard: arrows rotate, +/- zoom, 0 reset (via `listenToKeyEvents` on the focusable canvas wrapper). Hover shows the mail subject and case id; click selects a point, lists its 8 nearest neighbours in 3D with distances, highlights them, and links to `/investigation?open=<case id>` when present.
- Auto-rotate is off; under `prefers-reduced-motion` damping is off too. No decorative animation.
- Honest copy: "3 components explain <x>% of the variance. Closeness means similar embeddings, not the same campaign." No cluster is called a campaign.
- Fallbacks: no WebGL (feature test) or a render error boundary -> the 2D chart (fixed: fixed point size, axes fitted to the points, campaign rectangles optional and never extending the domain); a "View as table" toggle (sortable: subject, case, label, PC1-3) is the text alternative in all cases; the canvas wrapper has `role="group"`, an accessible name and a description with the counts per category.

### Rest of the page

- Layout: fixed, content-sized panels (see the layout section); no react-grid-layout, which removes the #185 resize crash.
- Per-panel loading/error/empty states (a slow PCA does not block counts and volume); plain error copy; empty state when the store has no data.
- Header: remove "Live"; subtitle "Organisation-wide, from the message store"; refresh button; theme tokens for text.
- Classification bars and the volume chart use result-palette colours, a legend for the areas, text summary for each chart (`role="img"` + `aria-label` and a "View as table" option), full campaign names in an accessible list with the note "Campaign windows are inferred from shared source references."
- Remove inline weights above 700 and letterSpacing; chips with white-on-colour text get `readableOnTint`.

## Global constraints

- Honest numbers: nothing displayed that the backend did not compute; the PCA caveat visible; empty data says so.
- No reporter data added; access unchanged.
- Bundle: the 3D chunk is lazy and only fetched on `/campaigns`; report its size gzip in the task report; main chunk size must not grow.
- Conventional Commits with trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; nothing pushed; never stage `deployment/compose_apps.yaml`; no `git stash`.
- Frontend gates: `npx vitest run`, `npx tsc -b`, `npx eslint .` (0 errors), e2e submit + ioc-road 7/7; backend `ww test backend api` green.
- 3D code must be testable: pure helpers (nearest neighbours, covariance ellipsoid, bounds, table sort) unit-tested without WebGL; the canvas is mocked in jsdom/browser tests; one real-browser capture per theme.

## Review focus

1. No WebGL / context lost / R3F error: the page still shows the 2D chart and the table, never a blank panel.
2. 0, 1, 2 points; all points identical (zero variance on an axis); a category with < 5 points (no ellipsoid, no NaN geometry).
3. 5000 points: interaction stays responsive (frameloop demand, instancing), memory freed on unmount (dispose geometry/material).
4. Keyboard-only user can rotate, zoom, reset, select a point (Tab to the point list/table) and open the investigation link; screen reader gets counts and the table.
5. Reduced motion, all 17 themes (point and cloud colours, labels, fog colour from theme background), phone width (touch rotate/pinch, no page scroll hijack: `touch-action` handled, a way to leave the canvas).

## New indicators, layout and redesign (added 2026-10-13, user: "come up with new indicators, change layout, enhance the rest of the page")

A campaign here = the set of messages sharing identical `sourceRefs` (a heuristic from the API itself). Everything below is computed from fields the message store already holds (classification, sent date, case id, subject, source refs, embedding); nothing is invented.

### Backend: one scan, one new endpoint

`GET /api/campaigns/summary/?days=7|15|30|90` (same `StatsReadPermission`, cached 120 s, one pass over `iter_metadata_dicts`) returns, for the period and the previous period of equal length:

- `messages` (total in store with a date in the period) and `dangerous_share` (dangerous / messages) with the previous period's values.
- `peak_day {date, count}`.
- `campaigns[]`: per source-ref group inside the period: `name`, `first_seen`, `last_seen`, `messages`, `dangerous`, `dangerous_share`, `sample_subject`, `case_ids` (up to `max_case_ids`, 20), `active` (last seen within 48 h of now: a stated constant). The list is the 200 largest (ties: most recently seen, then name); `campaigns_total` is the count before that cut, and `active_campaigns` and `largest_campaign` are computed before it. A Chroma page read that fails part-way makes the whole scan fail (empty, uncached payload) instead of returning a prefix as complete.
- `mix`: counts per classification (four buckets) for the period.
- Existing endpoints stay; `mail-volume` gains `days` (default 15, max 90) so the chart follows the selector; PCA points gain an additive `date` (UTC date or null).

Embedding-space indicators (own task, bounded to the PCA sample, chunked numpy cosine similarity, never an n x n matrix in memory) in `GET /api/campaigns/neighbours/?limit`:

- `near_known_bad`: non-dangerous messages whose k=10 nearest neighbours are >= 60 % Dangerous (k and threshold are named constants and returned in the payload), with case id, subject, share and nearest dangerous case: "review these".
- `novel`: messages in the last 7 days whose nearest-neighbour distance exceeds the 95th percentile of the sample (possible new campaigns), with the same fields. Both lists capped at 20 and labelled as heuristics.

### Page layout (replaces the 3-panel grid)

1. Header: title, "Organisation-wide, from the message store", period selector (7/15/30/90 days), refresh. No "Live" chip.
2. KPI strip (cards size to content, 3 columns desktop / stacked phone): Messages (delta vs previous period), Dangerous share (delta in points), Active campaigns (of N in period), Largest campaign (messages), Peak day. Deltas show "no data" when the previous period is empty.
3. Main row: 3D embedding map (about 2/3 width) beside a detail side panel: selected point (subject, case link, nearest neighbours) or, when nothing is selected, the "Near known bad" and "Novel" lists (each row selects its point in the map and focuses it).
4. Map colour modes (segmented control, `aria-pressed`): By category (default) | By campaign (top 6 campaigns coloured, the rest grey) | By age (recency ramp, legend with dates). A date range slider (from PCA `date`) filters visible points; no auto-play animation.
5. Volume row: stacked area chart (Dangerous vs Other) with campaign bands and a legend, beside the classification mix as a horizontal stacked bar with counts and percentages (text rows carry the meaning).
6. Campaigns table: sortable (first seen, last seen, messages, dangerous share), `Active`/`Ended` status as text, sample subject, "Open cases" (links to the investigations list filtered by the case ids when the list supports it, otherwise first case) and a row action "Show in map" (sets By campaign and selects its points). Mobile: card list.
7. Drag/resize layout customisation is dropped on this page (the panels are fixed and content-sized): fewer moving parts, no saved layouts to migrate, and the shared-grid extraction is only needed for the Dashboard. (Supersedes the earlier "share the layout code" decision for Campaigns; the #185 crash disappears with the grid.)

## Tasks (to be detailed in the plan)

1. Backend A: PCA third component + `date`, four classification buckets, `mail-volume?days`, `summary` endpoint with campaign aggregates; tests incl. degenerate inputs.
2. Backend B: `neighbours` endpoint (near known bad, novel) with bounded memory and tests (fixtures with synthetic embeddings, constant thresholds asserted).
3. Page foundation: new header/period selector, KPI strip, per-panel states, volume + mix charts with legends and text summaries, campaigns table, phone layout; remove the grid and "Live"; theme tokens and contrast.
4. 3D map: helpers (unit-tested), `EmbeddingMap3D` with colour modes, date filter, side panel lists, fallbacks, accessibility, bundle measurement.
5. Polish and verification: contrast sweep (7 themes), captures with real data, a11y, backlog.
