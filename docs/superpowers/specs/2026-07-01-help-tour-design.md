# In-App Help Tour (react-joyride) — Design

**Date:** 2026-07-01
**Component:** `suspicious-ui` frontend
**Goal:** A Help button that launches a guided walkthrough of the app using
[react-joyride](https://react-joyride.com), helping users learn to navigate.

## Decisions (locked with user)

- **Scope:** Global nav tour **+** per-page tours.
- **Button location:** Sidebar footer, beside the user card / logout button.
- **Auto-run:** Runs automatically on a user's first visit (localStorage flag),
  manual-only thereafter.

## Library

- **`react-joyride@^3`** (v3.0.2, April 2026). v3 is the first release
  compatible with **React 19** (this app is on React 19.2). v2.x is broken on
  React 19 — do not use it.
- v3 API (hook-based):
  ```tsx
  import { useJoyride } from "react-joyride";
  const { controls, on, state, Tour } = useJoyride({ continuous: true, steps });
  // controls.start(index?) launches; render {Tour} in JSX;
  // targets are CSS selectors — we use data-tour="..." attributes.
  ```

## Architecture

Three new files under `src/features/help/`, plus small edits to the layout.

### 1. `tourSteps.ts` — step registry

```ts
import type { Step } from "react-joyride";

// Shown on every page, first.
export const GLOBAL_STEPS: Step[] = [ /* nav sections, submit, help button, user card */ ];

// Keyed by route prefix. Matched longest-prefix against location.pathname.
export const PAGE_STEPS: Record<string, Step[]> = {
  "/submit": [ /* ... */ ],
  // more pages added incrementally
};

export function getStepsForPath(pathname: string): Step[]; // GLOBAL_STEPS + best PAGE_STEPS match
```

Targets are `data-tour="<name>"` attributes. Steps whose target is absent on
the current page are dropped by react-joyride (surfaced via `failures`); we
filter them out so a page only shows steps whose anchors exist.

### 2. `HelpTourProvider.tsx` — mount point + context

- Calls `useJoyride({ continuous: true, steps })` where `steps` comes from
  `getStepsForPath(useLocation().pathname)`, recomputed on route change.
- Renders `{Tour}` and its `children`.
- Exposes `{ start }` (wrapping `controls.start`) via a React context so the
  sidebar Help button — rendered elsewhere in the tree — can trigger it.
  (Context, not Zustand: zero new state lib, single consumer.)
- **Auto-run once:** on mount, if `localStorage["suspicious.tour.seen"] !== "1"`,
  call `controls.start()` and set the flag. Mirrors the existing
  `suspicious.sidebar.pinned` localStorage pattern in `AppLayout`.

### 3. `useHelpTour.ts` — `useContext` accessor hook

Thin `useHelpTour()` returning `{ start }`. Throws if used outside provider.

### Layout edits

- **`AppLayout.tsx`:** wrap the returned JSX in `<HelpTourProvider>…</HelpTourProvider>`
  so both the sidebar button and the page content sit inside it.
- **`navComponents.tsx`:** add `HelpButton({ slim })` (mirrors `LogoutButton`),
  calls `useHelpTour().start()`. Add `data-tour="help"` to it.
- **Anchor attributes:** add `data-tour="nav-primary"`, `data-tour="nav-workspace"`,
  `data-tour="user-card"`, `data-tour="help"` on the relevant sidebar elements;
  `data-tour="submit-form"` (or similar) on the Submit page as the exemplar
  per-page tour.

## Data flow

```
first visit ─┐
Help click ──┴─► HelpTourProvider.start() ─► controls.start()
                       │
   useLocation ────────┴─► getStepsForPath() ─► steps ─► useJoyride ─► {Tour} overlay
```

## Styling

Ship with react-joyride defaults first. MUI-theme-matched styling (pass
`styles`/CSS vars derived from `useTheme`) is a **follow-up**, not in scope for
the first cut — the tour is functional and readable without it.

## Testing

- `tourSteps.test.ts`: `getStepsForPath` returns global steps for an unknown
  route; returns global + page steps for `/submit`; longest-prefix match wins.
- `HelpTourProvider.test.tsx` (Vitest + RTL): renders children; auto-starts once
  when the localStorage flag is unset and not again when set; `start` from
  context is callable. Mock `react-joyride`'s `useJoyride` so tests don't depend
  on overlay rendering.
- Existing suite (85 tests) must stay green.

## Scope boundaries (YAGNI)

- **Per-page tours are scaffolded, not exhaustively authored.** Ship GLOBAL_STEPS
  + one exemplar page (`/submit`). The registry + `data-tour` convention make
  adding the remaining pages a copy-paste follow-up, tracked separately. Building
  all seven pages' tours up front is speculative until the pattern is validated.
- No custom tooltip component, no i18n of step copy, no theme-matched styling in
  v1 — all deferred.

## Risks

- **Missing targets** if a `data-tour` anchor is renamed/removed — react-joyride
  reports these via `failures`; we pre-filter steps to existing anchors so a
  broken anchor silently drops its step rather than showing an empty overlay.
- **React 19 peer dep** — resolved by pinning `react-joyride@^3`.
