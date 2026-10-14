# UI Theme Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship real webfonts, palette-driven borders, a verified contrast floor, a shared empty state and a per-theme visual review for the 17 themes of `suspicious-ui`.

**Architecture:** `themes.ts` keeps its `mkDark`/`mkLight`/`createTheme` structure. Fonts load once in `main.tsx` via Fontsource and the font stacks name the Fontsource families first. The shared `base` stops using two hardcoded colours and derives borders from each theme's own text colour. A contrast test and a Playwright contact-sheet script give a checked before/after for every theme.

**Tech Stack:** React 19, MUI 9.4, Vite 8, Vitest 4 (browser mode), Playwright, Fontsource, pnpm 11 on Node 22.

**Spec:** `docs/specs/2026-10-08-ui-theme-foundation-design.md`

## Global Constraints

- `high_contrast` stays WCAG AAA: text on background and on paper at least 7:1.
- Every other theme: text on background and on paper at least 4.5:1.
- Existing vitest, `tsc -b` and `eslint .` stay green after every task.
- New dependencies in this cycle: Fontsource packages only, latin subset, variable fonts where the family has one.
- No feature, route or backend change. Visual and UX only.
- Every design decision carries a one-line reason (anti-slop C-1). UI strings and comments touched here follow `ways-of-working:anti-slop-copywriting` and `anti-slop-code`.
- Toolchain: this host has Node 18. Use Node 22 and pnpm 11 as in memory note #48: `curl -sL -o node22.tar.xz https://nodejs.org/dist/v22.13.1/node-v22.13.1-linux-x64.tar.xz && tar xf node22.tar.xz && export PATH=$PWD/node-v22.13.1-linux-x64/bin:$PATH`, then `npx pnpm@11.1.3 install --frozen-lockfile` inside `suspicious-ui/`.
- Dev stack must be up for the capture script: UI on `http://localhost:9021`, login `elena.voss@meridian.example` / `MeridianDev!2026` (CLAUDE.md, E2E section).

## Review Focus

- A font file is blocked or fails to load (offline, strict CSP): text must stay readable in the fallback stack. Pinned in Task 2.
- `high_contrast` under forced colours or a palette edit: contrast must not drop below 7:1. Pinned in Task 4.
- EmptyState shown while data is still loading: it must not flash before the spinner. Pinned in Task 5.
- A theme that overrides `MuiPaper` itself must keep its own border and not inherit the new derived one. Pinned in Task 3.
- Switching theme at runtime after fonts load: no theme may resolve an empty `fontFamily`. Pinned in Task 2.

---

## File Structure

- Create `suspicious-ui/scripts/theme-sheets.mjs`: logs in, captures the three pages in every theme, writes PNGs and three contact sheets with captions below each image.
- Modify `suspicious-ui/package.json`, `pnpm-lock.yaml`: Fontsource packages.
- Modify `suspicious-ui/src/main.tsx`: font CSS imports.
- Modify `suspicious-ui/src/styles/themes.ts`: font stacks, `edge()` helper, `base` borders, palette fixes found by the contrast test, per-theme fixes from the review.
- Create `suspicious-ui/src/styles/__tests__/themes.test.ts`: font and `edge` tests.
- Create `suspicious-ui/src/styles/__tests__/contrast.test.ts`: contrast floor for all themes.
- Create `suspicious-ui/src/shared/components/EmptyState.tsx` and `__tests__/EmptyState.test.tsx`.
- Modify `suspicious-ui/src/pages/HomePage.tsx`, `features/dashboard/components/ThreatDistributionPanel.tsx`: use EmptyState, drop the misplaced `sun-orb` class on chart boxes.

---

### Task 1: Theme capture script and baseline

**Files:**
- Create: `suspicious-ui/scripts/theme-sheets.mjs`

**Interfaces:**
- Produces: `node scripts/theme-sheets.mjs <outDir>` writes `<outDir>/<theme>-<page>.png` (17 themes x 3 pages: `home`, `submissions`, `dashboard`) and `<outDir>/sheet-<page>-<n>.png`. Env: `UI_URL` (default `http://localhost:9021`), `UI_USER`, `UI_PASS`, `CHROMIUM_PATH` (optional executable).

- [ ] **Step 1: Write the script**

```js
import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";

const out = path.resolve(process.argv[2] ?? "theme-shots");
const url = process.env.UI_URL ?? "http://localhost:9021";
const THEMES = ["midnight","graphite","slate","light","paper","renee","high_contrast","sunrise","valentine","cyber","the_one","metal","winter","spring","summer","autumn","future"];
const PAGES = ["", "submissions", "dashboard"];
const name = (p) => p || "home";

fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch(
  process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {},
);
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();

await page.goto(`${url}/login`);
await page.getByRole("button", { name: /username and pass/i }).click();
await page.locator("input").first().fill(process.env.UI_USER ?? "elena.voss@meridian.example");
await page.locator("input[type=password]").fill(process.env.UI_PASS ?? "MeridianDev!2026");
await page.keyboard.press("Enter");
await page.waitForURL((u) => !u.pathname.startsWith("/login"));

for (const t of THEMES) {
  for (const p of PAGES) {
    await page.goto(`${url}/${p}`);
    await page.waitForLoadState("networkidle");
    // The server-saved theme overwrites localStorage after load, so switch through the store's own event.
    await page.evaluate((theme) => window.dispatchEvent(new CustomEvent("suspicious:theme-hydrate", { detail: { theme, autoSeasonal: false } })), t);
    await page.waitForTimeout(700);
    await page.screenshot({ path: path.join(out, `${t}-${name(p)}.png`) });
  }
}

// Captions sit under each image so they never cover the page.
const groups = [THEMES.slice(0, 6), THEMES.slice(6, 12), THEMES.slice(12)];
const sheetPage = await browser.newPage({ viewport: { width: 1938, height: 800 } });
for (const p of PAGES) {
  for (const [i, g] of groups.entries()) {
    const html = `<body style="margin:0;background:#777;display:grid;grid-template-columns:repeat(3,640px);gap:6px;font:bold 14px sans-serif">${g
      .map((t) => `<figure style="margin:0"><img width="640" src="file://${path.join(out, `${t}-${name(p)}.png`)}"><figcaption style="background:#000;color:#fff;padding:2px 6px">${t}</figcaption></figure>`)
      .join("")}</body>`;
    const f = path.join(out, "sheet.html");
    fs.writeFileSync(f, html);
    await sheetPage.goto(`file://${f}`);
    await sheetPage.screenshot({ path: path.join(out, `sheet-${name(p)}-${i + 1}.png`), fullPage: true });
  }
}
fs.rmSync(path.join(out, "sheet.html"));
await browser.close();
console.log(`wrote ${THEMES.length * PAGES.length} captures and ${PAGES.length * groups.length} sheets to ${out}`);
```

- [ ] **Step 2: Run it for the baseline**

Run from `suspicious-ui/` with Node 22 on PATH (baseline goes outside the repo): `node scripts/theme-sheets.mjs "$CLAUDE_JOB_DIR/tmp/ui-before"`
Expected: `wrote 51 captures and 9 sheets to ...`. If Playwright's pinned browser build is missing, set `CHROMIUM_PATH` to the installed headless shell under `~/.cache/ms-playwright/`.

- [ ] **Step 3: Check the sheets**

Open `sheet-home-1.png` and confirm the caption sits below each thumbnail and no page text is covered.

- [ ] **Step 4: Commit**

```bash
git add suspicious-ui/scripts/theme-sheets.mjs
git commit -m "chore(ui): add theme contact-sheet capture script"
```

---

### Task 2: Self-hosted fonts

**Files:**
- Modify: `suspicious-ui/package.json`, `suspicious-ui/pnpm-lock.yaml`, `suspicious-ui/src/main.tsx`, `suspicious-ui/src/styles/themes.ts:3-23`
- Create: `suspicious-ui/src/styles/__tests__/themes.test.ts`

**Interfaces:**
- Produces: `themes.<name>.typography.fontFamily` strings that start with the Fontsource family name: `"Inter Variable"` (sans), `"Source Serif 4 Variable"` (serif), `"Nunito Variable"` (rounded), `"IBM Plex Mono"` (mono).

- [ ] **Step 1: Verify packages and licences before installing**

Run:
```bash
for p in @fontsource-variable/inter @fontsource-variable/nunito @fontsource-variable/source-serif-4 @fontsource/ibm-plex-mono; do npm view $p name version license; done
```
Expected: each prints a name, version and `OFL-1.1` (or the font's own open licence). Read the Fontsource install docs (https://fontsource.org/docs/getting-started/install) to confirm the import paths used in Step 4. If a package name does not exist, stop and report instead of substituting.

- [ ] **Step 2: Write the failing test**

```ts
// src/styles/__tests__/themes.test.ts
import { describe, it, expect } from "vitest";
import { themes, type ThemeName } from "@/styles/themes";

const FIRST_FAMILY: Partial<Record<ThemeName, string>> = {
  light: "Inter Variable",
  midnight: "Inter Variable",
  paper: "Source Serif 4 Variable",
  renee: "Source Serif 4 Variable",
  sunrise: "Nunito Variable",
  high_contrast: "IBM Plex Mono",
  cyber: "IBM Plex Mono",
};

describe("theme fonts", () => {
  it("every theme resolves a non-empty font stack ending in a generic family", () => {
    for (const [name, theme] of Object.entries(themes)) {
      const stack = theme.typography.fontFamily ?? "";
      expect(stack, name).not.toBe("");
      expect(stack, name).toMatch(/(sans-serif|serif|monospace)$/);
    }
  });

  it("themes start their stack with the family that is actually bundled", () => {
    for (const [name, family] of Object.entries(FIRST_FAMILY)) {
      const stack = themes[name as ThemeName].typography.fontFamily ?? "";
      expect(stack.replace(/"/g, "").startsWith(family!), name).toBe(true);
    }
  });
});
```

- [ ] **Step 3: Run it to see it fail**

Run: `npx vitest run src/styles/__tests__/themes.test.ts`
Expected: FAIL on the second test (stacks still start with `Inter`, `"Iowan Old Style"`, `"Nunito"`).

- [ ] **Step 4: Install and wire the fonts**

```bash
npx pnpm@11.1.3 add @fontsource-variable/inter @fontsource-variable/nunito @fontsource-variable/source-serif-4 @fontsource/ibm-plex-mono
ls node_modules/@fontsource-variable/inter/*.css node_modules/@fontsource/ibm-plex-mono/latin-*.css | head -20
```
In `src/main.tsx`, above `import "@/bones/registry";`, add the latin-only CSS files you found (variable families import their `wght.css` only if no latin-only file exists; the `unicode-range` rule keeps unused subsets from downloading):
```ts
import "@fontsource-variable/inter/wght.css";
import "@fontsource-variable/nunito/wght.css";
import "@fontsource-variable/source-serif-4/wght.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-600.css";
import "@fontsource/ibm-plex-mono/latin-700.css";
```
In `themes.ts` change the four stacks so the bundled family comes first and the old names stay as fallbacks:
```ts
const sansStack = ['"Inter Variable"', "Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "Arial", "sans-serif"].join(",");
const serifStack = ['"Source Serif 4 Variable"', '"Iowan Old Style"', '"Palatino Linotype"', "Palatino", "Georgia", "serif"].join(",");
const roundedStack = ['"Nunito Variable"', "Nunito", "Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "Arial", "sans-serif"].join(",");
```
`monoStack` already starts with `"IBM Plex Mono"`; leave it.

Reason: the bundled family first removes the OS-dependent rendering (F1); the old names remain so a blocked font file still renders a sensible face (Review Focus 1).

- [ ] **Step 5: Run the test, then the type and lint checks**

Run: `npx vitest run src/styles/__tests__/themes.test.ts && npx tsc -b && npx eslint src/main.tsx src/styles`
Expected: all pass.

- [ ] **Step 6: Confirm the fonts load in a real browser**

Run: `pnpm build` (npx pnpm@11.1.3 build), record `dist` size, then rebuild the UI image or run `npx vite preview` and in Playwright evaluate `document.fonts.check('13px "Inter Variable"')`.
Expected: `true`, and Network shows `.woff2` files served from the app origin. Record the `dist` size delta in the commit message.

- [ ] **Step 7: Commit**

```bash
git add suspicious-ui/package.json suspicious-ui/pnpm-lock.yaml suspicious-ui/src/main.tsx suspicious-ui/src/styles
git commit -m "feat(ui): self-host Inter, Nunito, Source Serif 4 and IBM Plex Mono"
```

---

### Task 3: Borders follow the theme's own text colour

**Files:**
- Modify: `suspicious-ui/src/styles/themes.ts` (`base.components`, lines ~64-230)
- Modify: `suspicious-ui/src/styles/__tests__/themes.test.ts`

**Interfaces:**
- Produces: `export function edge(theme: Theme, a: number): string` in `themes.ts`. Returns `1px solid <alpha(theme.palette.text.primary, a)>`.

- [ ] **Step 1: Write the failing tests**

Append to `themes.test.ts`:
```ts
import { createTheme, alpha } from "@mui/material/styles";
import { edge } from "@/styles/themes";

describe("edge", () => {
  it("derives the border colour from the theme's text colour", () => {
    const t = createTheme({ palette: { mode: "dark", text: { primary: "#112233" } } });
    expect(edge(t, 0.1)).toBe(`1px solid ${alpha("#112233", 0.1)}`);
  });

  it("a theme that sets its own MuiPaper border keeps it", () => {
    // paper overrides MuiPaper; its override must still win over the shared base.
    const root = themes.paper.components?.MuiPaper?.styleOverrides?.root;
    const resolved = typeof root === "function" ? root({ theme: themes.paper } as never) : root;
    expect(JSON.stringify(resolved)).not.toContain(alpha("#E5E7EB", 0.1));
  });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npx vitest run src/styles/__tests__/themes.test.ts`
Expected: FAIL, `edge` is not exported.

- [ ] **Step 3: Implement**

In `themes.ts`, after the `border` helper add:
```ts
export const edge = (theme: Theme, a: number) => border(theme.palette.text.primary, a);
```
Add `type Theme` to the `@mui/material/styles` import. Then in `base.components`, replace each pair of
`theme.palette.mode === "dark" ? border("#E5E7EB", X) : border("#0B1220", Y)` (Paper, Card, Chip, Tooltip) with `edge(theme, theme.palette.mode === "dark" ? X : Y)`, and the `alpha("#E5E7EB", ...)`/`alpha("#0B1220", ...)` outline, divider, table head and row fills with `alpha(theme.palette.text.primary, <same alpha>)`. Keep every alpha number as it is.

Reason: the same alpha on the theme's own text colour tints borders and fills toward each theme's hue instead of a fixed blue-grey, without changing weight (F6).

- [ ] **Step 4: Run tests, types, lint**

Run: `npx vitest run src/styles && npx tsc -b && npx eslint src/styles`
Expected: pass.

- [ ] **Step 5: Compare visually**

Run: `node scripts/theme-sheets.mjs "$CLAUDE_JOB_DIR/tmp/ui-after-borders"` and compare `sheet-home-*.png` against the baseline. Expected: borders and table heads follow each theme's hue; no theme lost its border.

- [ ] **Step 6: Commit**

```bash
git add suspicious-ui/src/styles
git commit -m "feat(ui): derive shared borders and fills from each theme's text colour"
```

---

### Task 4: Contrast floor for every theme

**Files:**
- Create: `suspicious-ui/src/styles/__tests__/contrast.test.ts`
- Modify: `suspicious-ui/src/styles/themes.ts` (only the palette entries of themes that fail)

**Interfaces:**
- Consumes: `themes` and `ThemeName` from `themes.ts`.

- [ ] **Step 1: Write the test**

```ts
import { describe, it, expect } from "vitest";
import { themes, type ThemeName } from "@/styles/themes";
import { decomposeColor } from "@mui/material/styles";

function lum(color: string) {
  const [r, g, b] = decomposeColor(color).values.slice(0, 3).map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
const ratio = (a: string, b: string) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};
const flat = (c: string) => c; // text.secondary is alpha-blended below

function blend(fg: string, bg: string) {
  const f = decomposeColor(fg).values;
  const b = decomposeColor(bg).values;
  const a = f[3] ?? 1;
  return `rgb(${[0, 1, 2].map((i) => Math.round(f[i] * a + b[i] * (1 - a))).join(",")})`;
}

describe("theme contrast", () => {
  for (const [name, theme] of Object.entries(themes)) {
    const floor = (name as ThemeName) === "high_contrast" ? 7 : 4.5;
    const { text, background } = theme.palette;
    it(`${name}: primary text >= ${floor}:1 on background and paper`, () => {
      expect(ratio(flat(text.primary), background.default), "bg").toBeGreaterThanOrEqual(floor);
      expect(ratio(flat(text.primary), background.paper), "paper").toBeGreaterThanOrEqual(floor);
    });
    it(`${name}: secondary text >= ${floor}:1 on paper`, () => {
      expect(ratio(blend(text.secondary, background.paper), background.paper)).toBeGreaterThanOrEqual(floor);
    });
  }
});
```

- [ ] **Step 2: Run it**

Run: `npx vitest run src/styles/__tests__/contrast.test.ts`
Expected: some themes may FAIL. Record the list with the actual ratios in the commit message. If all pass, state that and skip Step 3.

- [ ] **Step 3: Fix each failing palette**

For each failing theme, change only the offending `text` or `paper`/`bg` hex in its `mkDark`/`mkLight` call (or `palette` block for `metal` and `future`), moving lightness the minimum amount that clears the floor. Re-run the test after each theme. Do not touch accent colours here.

- [ ] **Step 4: Full run**

Run: `npx vitest run src/styles && npx tsc -b`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add suspicious-ui/src/styles
git commit -m "test(ui): enforce text contrast floor on all themes"
```

---

### Task 5: Shared EmptyState

**Files:**
- Create: `suspicious-ui/src/shared/components/EmptyState.tsx`, `suspicious-ui/src/shared/components/__tests__/EmptyState.test.tsx`
- Modify: `suspicious-ui/src/pages/HomePage.tsx:333-390`, `suspicious-ui/src/features/dashboard/components/ThreatDistributionPanel.tsx:112-170`

**Interfaces:**
- Produces: `export function EmptyState(props: { icon?: React.ReactNode; title: string; hint?: string; action?: React.ReactNode }): JSX.Element`.

- [ ] **Step 1: Write the failing test**

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { EmptyState } from "@/shared/components/EmptyState";

describe("EmptyState", () => {
  it("shows title, hint and action", () => {
    render(<EmptyState title="No submissions yet" hint="Submit an item to see its verdict here." action={<button>Submit</button>} />);
    expect(screen.getByText("No submissions yet")).toBeInTheDocument();
    expect(screen.getByText(/verdict here/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Submit" })).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npx vitest run src/shared/components/__tests__/EmptyState.test.tsx`
Expected: FAIL, module not found.

- [ ] **Step 3: Implement**

```tsx
import * as React from "react";
import { Stack, Typography } from "@mui/material";

type Props = { icon?: React.ReactNode; title: string; hint?: string; action?: React.ReactNode };

export function EmptyState({ icon, title, hint, action }: Props) {
  return (
    <Stack spacing={0.75} sx={{ height: "100%", alignItems: "center", justifyContent: "center", textAlign: "center", color: "text.secondary", px: 2 }}>
      {icon}
      <Typography variant="body1" sx={{ fontWeight: 650, color: "text.primary" }}>{title}</Typography>
      {hint && <Typography variant="body2">{hint}</Typography>}
      {action}
    </Stack>
  );
}
```

- [ ] **Step 4: Use it where the chart is empty**

In `HomePage.tsx` and `ThreatDistributionPanel.tsx`, replace the `No data` `<Stack>` branch with
`<EmptyState title="No submissions this month" hint="Verdicts appear here after your first analysis." />` (the `isLoading` branch with the spinner stays first, so EmptyState never shows during loading). In the same two places remove `className={...hasHeatEffect ? "sun-orb" : undefined}` from the chart `Box`: that class is the logo orb and paints a white block behind the empty chart in `summer`.

Reason: one component replaces two copies of the same blank block (F4), and the stray class is the cause of the summer white box.

- [ ] **Step 5: Pin the loading case**

Add to the existing HomePage or ThreatDistributionPanel test file (find it with `ls src/pages/__tests__ src/features/dashboard/components/__tests__`) a case that renders with the query still loading and asserts `screen.queryByText("No submissions this month")` is null. If no such test file exists for the touched component, add the case to `EmptyState.test.tsx` by rendering the loading branch's condition in a minimal wrapper and say so in the commit.

- [ ] **Step 6: Run checks**

Run: `npx vitest run src/shared src/pages src/features/dashboard && npx tsc -b && npx eslint src`
Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add suspicious-ui/src
git commit -m "feat(ui): shared EmptyState; drop logo orb class from chart boxes"
```

---

### Task 6: Per-theme visual review, three groups

Groups: dark neutrals and light neutrals (`midnight graphite slate light paper renee`), `high_contrast` and terminal themes (`high_contrast cyber metal future`), seasonal and character themes (`sunrise valentine the_one winter spring summer autumn`).

**Files:**
- Modify: `suspicious-ui/src/styles/themes.ts` (only the theme blocks listed per group)

**Interfaces:**
- Consumes: `THEME_CAPABILITIES[<theme>].description` from `ThemeStore.tsx` as the identity line for each theme.

For each group, repeat these steps:

- [ ] **Step 1: Capture**

Run: `node scripts/theme-sheets.mjs "$CLAUDE_JOB_DIR/tmp/ui-group-N"` and open the group's three sheets (home, submissions, dashboard).

- [ ] **Step 2: Check each theme against four questions and list defects**

For every theme: (a) does it look like its `description`? (b) does the primary action read clearly on both paper and background? (c) are there blocks that ignore the theme (white or black patches)? (d) is the type face the one the theme intends (serif for `paper`/`renee`, mono for terminal themes)? Write each defect as one line in the commit message body with the page where it shows.

- [ ] **Step 3: Fix one defect at a time**

Change only that theme's block in `themes.ts`. Reason in one line per change (anti-slop C-1). Re-capture and compare. If a fix would need a change outside `themes.ts`, stop and add it to `docs/plans/ui-redesign-backlog.md` instead.

- [ ] **Step 4: Run checks**

Run: `npx vitest run src/styles && npx tsc -b && npx eslint src/styles`
Expected: pass, including the Task 4 contrast test.

- [ ] **Step 5: Commit the group**

```bash
git add suspicious-ui/src/styles
git commit -m "feat(ui): per-theme visual pass, <group name>"
```

---

### Task 7: Final verification and delivery report

- [ ] **Step 1: Full suite**

Run: `npx vitest run && npx tsc -b && npx eslint . && npx pnpm@11.1.3 build`
Expected: all green. Record test count, lint warnings and the `dist` size against the pre-change size.

- [ ] **Step 2: Before and after**

Run the capture script once more into `$CLAUDE_JOB_DIR/tmp/ui-after` and compare each sheet with `ui-before`. Expected: webfonts visible, borders tinted per theme, no white block in summer, EmptyState in place.

- [ ] **Step 3: Anti-slop delivery report**

State PASS or FAIL with the evidence for each: any claim without a source; any fabricated content; any decision without a one-line reason; anything delivered without being run; UI strings and comments checked against `anti-slop-copywriting` and `anti-slop-code`.

- [ ] **Step 4: Save to memory and update the backlog**

Save a `mem_save` note with what shipped and what the review deferred, and append deferred items to `docs/plans/ui-redesign-backlog.md`.

- [ ] **Step 5: Commit**

```bash
git add docs/plans/ui-redesign-backlog.md
git commit -m "docs(ui): record theme foundation outcome and deferred items"
```

---

## Self-review

- **Spec coverage:** F1 and F5 (type) are Task 2; F2 and F6 are Tasks 3 and 6; F3 was withdrawn in the spec; F4 is Task 5; F7 is left alone as the spec says; verification and delivery gate are Tasks 1, 4 and 7.
- **Placeholders:** the only open choice is Task 4 Step 3 and Task 6 Step 3, which depend on measured results by design; both state the rule and the check.
- **Type consistency:** `edge(theme, a)` is defined in Task 3 and only used there; `EmptyState` props match between Task 5 steps; font family names match between the Task 2 test and stacks.
