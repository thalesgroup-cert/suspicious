# UI theme foundation: design

Date: 2026-10-08. Scope: `suspicious-ui/src/styles/*`, `layouts/AppLayout.tsx`, shared components. Page-by-page work follows in later cycles (see `docs/plans/ui-redesign-backlog.md`).

## Intent

Make the UI look current and make each of the 17 themes look like what it is named after, without changing features, routes or backend behavior. This cycle builds the foundation that every page inherits. Pages come after.

Constraints:
- `high_contrast` stays WCAG AAA.
- Existing vitest, tsc and eslint stay green.
- Every design choice below carries a one-line reason (anti-slop C-1). A choice without one is dropped.
- Dependencies are verified against official docs before use. New packages are added only where listed here.

## Audit findings

Evidence: Playwright captures of all 17 themes on Home, Submissions and Dashboard against the dev stack, 2026-10-08, plus a read of `styles/themes.ts`.

| # | Finding | Evidence |
|---|---|---|
| F1 | No webfont is loaded. Inter, Nunito and IBM Plex Mono are named in the font stacks but nothing ships them, so the OS fallback renders. | No `@font-face`, Fontsource or Google Fonts reference in `src/`, `index.html`, `public/`; screenshots |
| F2 | Themes differ almost only by palette. Radius, density, elevation and layout are the same in all 17. | Contact sheets |
| F3 | Withdrawn. The apparent header clip was my contact-sheet label drawn over the page; raw screenshots show the header intact. | Raw `high_contrast-home.png` |
| F4 | Empty states waste space and break themes: the empty donut takes about 250px for "No data", and in summer the empty chart sits in a white box. | Home sheets |
| F5 | Typography is small and flat: 13px base and one weight family for headings. | `base` in `themes.ts` |
| F6 | Borders, fills and tooltip colours are hardcoded (`#E5E7EB`, `#0B1220`) in the shared `base`, so Paper, Card, Chip, Divider and Tooltip look the same in every theme. | `themes.ts` |
| F7 | 17 themes and 14 capability flags live in one 4.9k-line file. | `themes.ts` |

## Design

### 1. Fonts (F1, F5)
Self-host variable fonts through Fontsource packages, imported once in `main.tsx`, `font-display: swap`, latin subset only.
- Inter for the default sans.
- A serif face for `paper` and `renee`.
- Nunito for the rounded stack.
- IBM Plex Mono for the terminal themes (`cyber`, `metal`, `future`).

Reason: the MUI docs describe self-hosted `@font-face` as the supported approach, and a self-hosted file avoids a third-party request from a corporate network. Typography is the strongest "old looking" signal and the precondition for distinct theme character.

Before install: read the Fontsource docs and confirm the package names, the subset imports and the licence. The new packages are the only new dependencies in this cycle.

### 2. Theme tokens (F2, F6)
Replace the hardcoded values in `base` with a small per-theme token object that each theme fills in:
- `border` (colour and alpha), `surface` fills for hover and head rows, `radius`, `focusRing`.
- `base` components read tokens from the theme instead of constants. MUI's own guidance is to put shared behavior in `styleOverrides` and `variants` and keep per-instance changes in `sx`. This follows that split.

Reason: the flat look has one cause, the constants. Fixing it in `base` once fixes every component in every theme.

### 3. Per-theme character (F2)
Each theme gets a two-line identity written next to its definition (what it represents, what it changes). Then radius, type, elevation and effects are tuned to match.
- Dark neutrals (`midnight`, `graphite`, `slate`): calm, low-glow, differ in surface hue and radius.
- Light neutrals (`light`, `paper`, `renee`): `paper` and `renee` get serif headings and softer borders.
- `high_contrast`: solid borders, no alpha fills, contrast verified by a script that fails the test run below 7:1 for text.
- Terminal themes (`cyber`, `metal`, `future`): mono for labels and table heads, square radius, scanline and glow effects only where a capability flag already exists.
- Seasonal and character themes (`winter`, `spring`, `summer`, `autumn`, `sunrise`, `valentine`, `the_one`): palette plus one signature detail each, kept within the existing capability flags.

Reason: a theme should be recognisable from a cropped screenshot. If a tuning choice has no reason beyond "it looks good", it is dropped.

### 4. Empty states (F4)
- Add one shared `EmptyState` component (icon, one line, optional action) and use it where the dashboard and home charts have no data. It uses theme tokens, so summer's white box goes away.

Reason: the same blank "No data" block is duplicated in `HomePage.tsx` and `ThreatDistributionPanel.tsx`, so one component fixes both.

### 5. Out of scope in this cycle
- Moving to `cssVariables` and `colorSchemes`. The MUI docs say it prevents dark-mode flicker and speeds up switching, but the app has 17 themes rather than a light/dark pair and no server rendering. Revisit if theme switching shows a measurable lag.
- Splitting `themes.ts` into files. Done only if the token work makes the file harder to review; otherwise left alone.
- Any page-level layout change. That belongs to the page cycles.

## Verification

Each step is checked by output, not by claim:
- `pnpm lint`, `tsc -b`, `vitest run` (Node 22 and pnpm 11, per the project's toolchain note).
- A contrast test for `high_contrast` covering text on background and text on paper.
- Playwright contact sheets for all 17 themes on Home, Submissions and Dashboard, taken before and after, reviewed against the identity lines in section 3.
- Fonts: confirm in the network panel and by computed `font-family` that the files load and no theme falls back.

## Delivery gate (anti-slop)

Before calling the cycle done, state PASS or FAIL with evidence for: any claim without a source, any fabricated content, any decision without a one-line reason, anything delivered without being run. UI strings and code comments touched in this cycle also pass the copywriting and code-comment checks.

## Risks

- Fontsource adds dependencies and bundle size. Mitigation: variable fonts, latin subset, only the families listed above, and a before/after build size check.
- Token changes touch every themed component. Mitigation: do it behind unchanged component names, run the full suite after each step, and compare contact sheets.

## Amendments after implementation

- Tokens: the planned token object (radius, focusRing) became the `edge()` helper. Because mkDark/mkLight merge `components` one level deep, a theme's own MuiPaper/MuiCard/MuiChip/MuiTooltip/MuiOutlinedInput override replaces the base, so `edge()` in base reaches only themes without those overrides (autumn, summer, the sidebar border). The visible card border fix came from the SoftCard changes. mkLight's three hardcoded #0B1220 entries (MuiOutlinedInput, MuiPaper, MuiCard) intentionally stay.
- Fonts: the three variable packages ship no latin-only CSS, so `wght.css` is imported (unicode-range limits what browsers download; dist +668 KB). The plan sanctioned this fallback.
