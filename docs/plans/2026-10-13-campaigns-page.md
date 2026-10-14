# Campaigns Page Redesign and 3D Embedding Map Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give analysts a campaigns page with real indicators (messages, dangerous share, campaigns table, near-known-bad and novel lists) and a rotatable 3D map of the email clouds, replacing the three-chart draggable grid.

**Architecture:** The backend adds a third PCA component, four classification buckets, a period-aware volume series, one aggregation endpoint (`/api/campaigns/summary/`) and a bounded nearest-neighbour endpoint (`/api/campaigns/neighbours/`), all read-only on the existing message store. The frontend replaces the grid with a fixed content-sized layout and lazy-loads a React Three Fiber map with 2D/table fallbacks.

**Tech Stack:** Django/DRF, numpy, ChromaDB (backend `Suspicious/Suspicious/api/services/campaigns/`); React 19, MUI 9, TanStack Query, recharts 3.10, `three` + `@react-three/fiber` v9 + `@react-three/drei` (frontend `suspicious-ui/`).

**Spec:** `docs/plans/2026-10-13-campaigns-page-design.md` (binding).

## Global Constraints

- Honest numbers only: nothing displayed that the backend did not compute; heuristics (campaign = identical `sourceRefs`, near-known-bad, novel) are labelled as such; empty data says so; deltas show "no data" when the previous period is empty.
- Access unchanged (`StatsReadPermission`); the page is labelled "Organisation-wide, from the message store".
- Backend changes are additive (old fields stay; `explained_variance` accepts 2 or 3 values; `z` and `date` optional) except `classification-counts`, which now returns four buckets (update the frontend in the same task).
- The 3D chunk is lazy (only fetched on `/campaigns`); the main bundle must not grow; report the gzip size of the 3D chunk.
- No react-grid-layout on this page; remove its CSS imports and layout storage code (`utils.ts` layout helpers) if unused elsewhere (grep first: the Dashboard has its own `features/dashboard/layout.ts`).
- Frontend: reuse `EmptyState`, `ensureContrast`/`readableOnTint`, `useResultHex`/`useStatusColors`, theme typography (`pageTitle`, `subtitle2`, `caption`); no inline `fontWeight` > 700 or `letterSpacing`; no text below the theme caption size; chart colours from the result palette, never literals; every text/mark meets contrast (4.5:1 text, 3:1 marks) in all 17 themes (sweep 7 incl. metal, future).
- Accessibility: charts have `role="img"` + summary label and a table alternative; the 3D map is operable by keyboard (arrows rotate, +/- zoom, 0 reset, Tab to the point list), reduced motion disables damping and animation, auto-rotate off; WebGL failure falls back to 2D + table.
- Conventional Commits, trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; nothing pushed; never stage `deployment/compose_apps.yaml`; no `git stash`.
- Gates: `npx vitest run`, `npx tsc -b`, `npx eslint .` (0 errors), e2e submit + ioc-road 7/7 (`e2e/investigation.spec.ts` keeps only main's 2 known failures); backend `ww test backend api` from the repo (Docker image bakes the code: rebuild `suspicious` before live captures). Node 22: `export PATH=$CLAUDE_JOB_DIR/tmp/node-v22.13.1-linux-x64/bin:$PATH`; pnpm only via `npx pnpm@11.1.3`.

## Review Focus

1. No WebGL / context lost / R3F error: 2D chart and table still render; never a blank panel.
2. 0, 1, 2 points; all points identical (zero variance on an axis); a category with < 5 points (no ellipsoid, no NaN geometry).
3. 5000 points: responsive (frameloop demand, instancing); geometry/material disposed on unmount.
4. Keyboard-only and screen-reader use: rotate, zoom, reset, select via list/table, open the case link; counts announced.
5. Empty store, ChromaDB unavailable (collection None), one panel failing while others load; period with no data; previous period empty (delta "no data").

## File Structure

- Backend: modify `api/services/campaigns/service.py`, `metadata.py`, `api/serializers/campaigns.py`, `api/views/campaigns.py`, `api/urls.py`; create `api/services/campaigns/summary.py` (aggregation) and `neighbours.py` (kNN, outliers); tests in `api/tests/test_campaigns_*.py` (create), docs in `docs/` if an API doc lists campaigns endpoints (grep).
- Frontend: rewrite `src/pages/CampaignsPage.tsx`; modify `features/campaigns/api.ts`, `utils.ts`; delete `components/grid.tsx` if unused; create `components/{CampaignKpis,CampaignTable,VolumeChart,MixBar,EmbeddingMap,EmbeddingMap3D,Embedding2D,PointTable,SidePanel,PeriodSelect}.tsx`, `features/campaigns/geometry.ts` (pure helpers); tests next to them and `pages/__tests__/CampaignsPage.test.tsx`.

---

### Task 1: Backend A: PCA 3rd component, buckets, volume period, summary endpoint

**Interfaces (produces):**
- `GET /api/campaigns/pca/?limit` points: `{x, y, z, label, suspicious_case_id, mail_subject, sourceRefs, date: "YYYY-MM-DD"|null}`; `explained_variance`: list of 2 or 3 floats.
- `GET /api/campaigns/classification-counts/` -> `{SAFE, UNWANTED, SUSPICIOUS, DANGEROUS}` (no folding).
- `GET /api/campaigns/mail-volume/?days=15` (7..90, default 15) -> same shape as today with `dates` of length `days`.
- `GET /api/campaigns/summary/?days=15` -> `{days, period:{start,end}, messages, previous_messages, dangerous, previous_dangerous, dangerous_share, previous_dangerous_share, peak_day:{date,count}|null, mix:{SAFE,UNWANTED,SUSPICIOUS,DANGEROUS}, campaigns:[{name, first_seen, last_seen, messages, dangerous, dangerous_share, sample_subject, case_ids:[str] (<=20), active:bool}], active_campaigns:int, largest_campaign:{name,messages}|null}`. `active` = `last_seen` within `ACTIVE_WINDOW_HOURS = 48` of now (constant, returned as `active_window_hours`). Campaign key = tuple of `parse_source_refs`; messages without source refs are not campaigns. One pass over `iter_metadata_dicts` for the period and the previous equal-length period; cache 120 s keyed by `days`.

- [ ] **Step 1: Failing tests** (fake collection with metadata/embeddings, as existing campaign code allows monkeypatching `get_chroma_collection`; read `api/tests/test_security_access.py` and `service.py` for the seams): PCA returns `z` and 3 ratios summing <= 1; degenerate inputs (1 vector, 1-dim vectors, 2 vectors -> `z=0`, ratio list valid, no NaN); `date` extracted via `extract_metadata_datetime`, null when missing; counts return four buckets with SUSPICIOUS not folded; `days` validation (6 and 91 -> 400, default 15); summary: totals, previous-period split at the boundary, dangerous share, peak day tie-break (earliest), campaign grouping by identical refs, messages without refs excluded, `active` flag with a frozen clock, case ids capped at 20, `largest_campaign`, empty store (collection None) returns zeros and empty lists, non-elevated user -> 403.
- [ ] **Step 2: Run, verify fail** (`ww test backend api.tests.test_campaigns_summary` or the docker equivalent used by earlier tasks).
- [ ] **Step 3: Implement** (serializers with `explained_variance` min_length 2 / max_length 3, new response serializers, `summary.py`, views, urls, OpenAPI descriptions; `classification_bucket_for_counts` no longer folds).
- [ ] **Step 4: Full backend gate** `ww test backend api dashboard` green; paste counts.
- [ ] **Step 5: Commit** `feat(campaigns): third PCA component, four buckets, period volume and campaign summary`.

### Task 2: Backend B: neighbours endpoint

**Interfaces (produces):** `GET /api/campaigns/neighbours/?limit=1500` -> `{k:10, bad_share_threshold:0.6, novelty_percentile:95, novel_window_days:7, near_known_bad:[Item], novel:[Item]}` with `Item = {suspicious_case_id, mail_subject, label, date, score, nearest_dangerous_case_id|null}`; lists capped at 20, ordered by score descending. `near_known_bad`: non-dangerous sampled messages whose k nearest neighbours (cosine similarity on the raw embeddings, self excluded) have a Dangerous share >= threshold; `score` = that share. `novel`: messages dated within the last 7 days whose nearest-neighbour cosine distance exceeds the 95th percentile of the sample's nearest-neighbour distances; `score` = distance. Memory bounded: similarity computed in chunks of at most 512 rows against the sample matrix (never n x n); sample size capped by `MAX_PCA_LIMIT`; fewer than `k + 1` vectors -> both lists empty.

- [ ] **Step 1: Failing tests** with synthetic embeddings (two tight clusters, one Dangerous and one Safe, a few safe points inside the dangerous cluster, one far outlier dated today): near-known-bad finds exactly the planted points; novel finds the outlier and not older ones; k larger than the sample -> empty; ties and duplicates (identical vectors, zero vectors) handled without NaN; chunking gives the same result with chunk size 2 as with 512 (parametrise the constant); non-elevated -> 403; empty collection -> empty lists.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `neighbours.py` (numpy, normalised vectors, `argpartition`), serializer, view, url; cache 120 s per limit.
- [ ] **Step 4: Backend gate; Step 5: Commit** `feat(campaigns): near-known-bad and novel message indicators`.

### Task 3: Page foundation, indicators, charts, campaigns table

**Interfaces:** consumes Task 1-2 endpoints; produces typed `api.ts` (`getCampaignSummary(days)`, `getMailVolume(days)`, `getClassificationCounts()`, `getPca(limit)`, `getNeighbours(limit)`, all normalised with numbers defaulting to 0 and nullable fields typed); `CampaignsPage` with a `days` state (7/15/30/90, default 15) in the query keys; panels exposing `onSelectCases(caseIds: string[])` / `selectedCaseIds` props for Task 4's map linkage (stub: stored in page state).

- [ ] **Step 1: Failing tests** (`CampaignsPage.test.tsx` rewrite + component tests; matchMedia stub like `SubmissionsPage.test.tsx`): header has no "Live", subtitle "Organisation-wide, from the message store", period selector refetches with `days`; KPI cards: Messages with delta vs previous ("no data" when previous 0), Dangerous share delta in points, Active campaigns "of N", Largest campaign, Peak day; each panel loads/fails/empties independently (one rejected query leaves the others rendered, plain error text with Retry, no "API routes" wording); empty store -> `EmptyState` "No messages in this period"; VolumeChart has a legend naming both areas, `role="img"` with a summary label ("Messages per day, <n> dangerous, peak <date>") and a "View as table" toggle; MixBar lists four classes with counts and percentages as text; CampaignTable sortable (aria-sort), status text Active/Ended, sample subject, "Open cases" link, "Show in map" calls `onSelectCases`; campaign names shown in full (no truncation) with the "inferred from shared source references" note; phone viewport renders the table as a card list, no horizontal scroll; no `react-grid-layout` import remains on the page (grep test or lint).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** page and components; delete grid code and layout storage if unused elsewhere; chart colours via result palette; keep the 2D scatter as `Embedding2D` (fixed point size, axes fitted to the points, no domain-extending reference areas) in the map slot until Task 4.
- [ ] **Step 4: Visual verification:** rebuild images (`cd deployment && docker compose --env-file .env build suspicious suspicious_ui && docker compose --env-file .env up -d suspicious suspicious_celery suspicious_celery_beat suspicious_ui`), Playwright (login ONCE, reuse `storageState`; theme set after load with 3 s settle via the `suspicious:theme-hydrate` event; elena.voss@meridian.example / MeridianDev!2026): 1440x900 and 390x844 in light, midnight, paper, high_contrast, cyber; VIEW all; `scrollWidth <= innerWidth` at 390. The dev store has one campaign; for richer captures seed a fixture ONLY in a throwaway way (temporary Chroma records with `sourceRefs`, dates, classifications) and DELETE it afterwards, recording ids; verify counts are back.
- [ ] **Step 5: Gates; commit** `feat(ui): campaigns indicators, volume, mix and campaigns table`.

### Task 4: 3D embedding map

**Interfaces:** `EmbeddingMap({points, explainedVariance, neighbours, selectedCaseIds, onSelectCases})` chooses `EmbeddingMap3D` (lazy `React.lazy`) when WebGL is available and no error, else `Embedding2D`; `PointTable` always available via a "View as table" toggle. `geometry.ts` (pure, unit-tested): `bounds(points)`, `categoryEllipsoid(points) -> {center, axes:[3x3], radii}|null` (null under 5 non-degenerate points; Jacobi eigen decomposition of the 3x3 covariance, radii = 2 sigma), `nearest(points, index, k)`, `recencyRamp(date, min, max)`, `topCampaignColours(campaigns, 6)`.

- [ ] **Step 1: Failing tests:** geometry helpers (0/1/2 points, identical points, zero variance axis, collinear points, 4 vs 5 points, known covariance gives known radii within tolerance, nearest ordering, ramp bounds); `EmbeddingMap` falls back to `Embedding2D` when the WebGL feature test fails and when the lazy chunk throws (error boundary); canvas wrapper `role="group"` with accessible name and description "N messages: <counts per category>"; chips `aria-pressed` toggle category visibility; colour-mode segmented control (category | campaign | age) with legends (age legend shows dates); date range slider filters the visible count announced in a live region; selecting a point (via table row or list) shows subject, case link `/investigation?open=<id>` and 8 nearest neighbours with distances; keyboard handler maps arrows/+/-/0 to the controls API (test the handler with a fake controls object); `prefers-reduced-motion` -> damping off; text states "<x>% of the variance in 3 components. Closeness means similar embeddings, not the same campaign."; `SidePanel` shows near-known-bad and novel lists (rows select and focus the point; labelled as heuristics; empty states).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `three`, `@react-three/fiber`, `@react-three/drei` (install with `npx pnpm@11.1.3 add`), `frameloop="demand"` + `invalidate` on controls `change`, `InstancedMesh` (per-instance colour/size by distance), fog from the theme background, axes labels with variance, category ellipsoids (transparent, `depthWrite` off), dispose on unmount, adaptive pixel ratio (`PerformanceMonitor`), `touch-action` so the page can still scroll and a visible "Skip map" link before the canvas. Measure `pnpm build` chunk sizes (before/after, gzip) and record; if the 3D chunk exceeds 450 kB gzip, switch to plain `three` + `three/examples/jsm/controls/OrbitControls` and say so.
- [ ] **Step 4: Visual verification** with real data (use the fixture from Task 3 with several categories/campaigns; or generate 1500 synthetic points through the real endpoint seam): 1440 and 390 in light, midnight, paper, high_contrast, cyber; each colour mode; VIEW all; confirm the clouds are visible and labelled, WebGL-off fallback (launch Chromium with `--disable-gpu --disable-webgl` for one capture), 5000-point responsiveness note (FPS or frame time via `performance.now` during a programmatic orbit).
- [ ] **Step 5: Gates; commit** `feat(ui): 3D embedding map with category clouds, colour modes and fallbacks`.

### Task 5: Polish, accessibility, contrast and final verification

- [ ] **Step 1: Failing tests** for anything found in a keyboard-only and heading-outline pass (h1 then h2 per panel, unique region names, tables with captions, focus order canvas wrapper -> skip link -> list), reduced-motion, Retry buttons.
- [ ] **Step 2: Contrast sweep** (Playwright, 7 themes incl. metal and future, 1440 and 390, every visible text node; marks 3:1 for chart colours and ellipsoids over the canvas background); fix page-owned failures with `ensureContrast`; list shared failures without changing them; save the table under the sdd directory and copy a summary to `docs/plans/campaigns-contrast-2026-10.tsv`.
- [ ] **Step 3: Final verification:** full vitest, `tsc -b`, eslint, backend `ww test backend api dashboard`, e2e 7/7, `investigation.spec.ts` vs main's 2 failures; final captures viewed; anti-slop delivery report (claims with a source, no fabricated content, decisions with a one-line reason, everything run, UI strings and comments); bundle numbers; backlog (per-country scoping needs reporter metadata in the store; live-refresh; campaign detail page); delete any fixture data; commit `fix(ui): campaigns accessibility and contrast`.

## Self-review

- Spec coverage: third component + date + four buckets + volume period + summary (Task 1); near-known-bad and novel (Task 2); header, KPI strip, volume + mix, campaigns table, states, no Live, no grid (Task 3); 3D map, colour modes, date filter, side panel, fallbacks, accessibility, bundle (Task 4); contrast, a11y, verification (Task 5).
- Placeholders: none; each test list names the assertions and each interface names fields.
- Type consistency: endpoint field names and `Item`/`campaign` shapes are identical in Tasks 1-4; constants (`ACTIVE_WINDOW_HOURS=48`, `k=10`, `0.6`, `95`, `7 days`) are returned in payloads so the UI text cannot drift.
