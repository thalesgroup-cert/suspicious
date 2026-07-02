# Schema-driven Avatar Customization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user pin specific DiceBear categories (hair, eyes, mouth, colors, …) via carousels, driven automatically from each style's own option schema, while the seed still randomizes everything they haven't pinned.

**Architecture:** Extend the stored avatar config from `{style, seed}` to `{style, seed, options}` where `options` maps a DiceBear category key to a one-element array pinning a value. The frontend reads each style's `schema.properties` at runtime to build one carousel per enum category; the backend accepts `options` with size caps only (no schema cross-check). Reuses the existing `PATCH /api/profile/appearance/` endpoint — no new endpoint, no migration (field is already `JSONField`).

**Tech Stack:** React 19 + TypeScript + MUI v9, TanStack Query v5, Vitest (browser/playwright provider), `@dicebear/core` + `@dicebear/collection` v9, Django REST Framework.

## Global Constraints

- DiceBear renders **client-side only** — bundled library, no `api.dicebear.com`.
- Stored config shape: `{ style: string, seed: string, options?: Record<string, string[]> }`, or `{}` to clear (fall back to initials). Backward compatible: `{style, seed}` with no `options` reproduces current behavior.
- `options` semantics: a category present pins that choice (single-element array); absent = seed-driven random. Randomize rerolls `seed` only, never touches `options`.
- Backend `options` caps (bounded/loose, no schema cross-check): dict, ≤ **20** keys; each key a string len 1..**32**; each value a string or list of strings, each string len 1..**64**, ≤ **20** items per list; total serialized `options` ≤ **2048** bytes.
- Allowed styles unchanged: `bottts`, `identicon`, `initials`, `avataaars`, `funEmoji`, `thumbs`, `shapes`, `notionists`.
- Frontend tests: `CI=true pnpm test <path>` from `suspicious-ui/` (Vitest uses the playwright browser provider; always pass a path to scope the run). Backend tests: `python manage.py test <path>` from `Suspicious/Suspicious/` (or inside the web container via `cd deployment && make shell`).
- Conventional Commits for messages.

---

### Task 1: Extend the avatar render helper with options + category extraction

**Files:**
- Modify: `suspicious-ui/src/features/profile/avatar.ts`
- Modify: `suspicious-ui/src/features/profile/__tests__/avatar.test.ts`

**Interfaces:**
- Consumes: `@dicebear/core` `createAvatar`, the `AVATAR_STYLES` collection style objects (each exposes a `schema` property).
- Produces:
  - `type AvatarConfig = { style: string; seed: string; options?: Record<string, string[]> }`
  - `renderAvatarDataUri(config: AvatarConfig): string` (now honors `options`)
  - `getStyleCategories(styleKey: string): { key: string; label: string; values: string[] }[]`
  - `randomSeed(): string` (unchanged)

- [ ] **Step 1: Write the failing tests**

Append these cases to `suspicious-ui/src/features/profile/__tests__/avatar.test.ts` (inside the existing `describe("avatar helper", …)` block):

```ts
  it("renders deterministically with options and changes when an option changes", () => {
    const base = renderAvatarDataUri({ style: "avataaars", seed: "abc123" });
    const withOpt = renderAvatarDataUri({
      style: "avataaars",
      seed: "abc123",
      options: { eyes: ["happy"] },
    });
    const withOptAgain = renderAvatarDataUri({
      style: "avataaars",
      seed: "abc123",
      options: { eyes: ["happy"] },
    });
    expect(withOpt).toBe(withOptAgain); // deterministic
    expect(withOpt).not.toBe(base); // pinning a category changes the render
  });

  it("keeps the no-options render identical to a plain {style, seed}", () => {
    const a = renderAvatarDataUri({ style: "bottts", seed: "abc123" });
    const b = renderAvatarDataUri({ style: "bottts", seed: "abc123", options: {} });
    expect(a).toBe(b);
  });

  it("extracts enum categories from a style schema", () => {
    const cats = getStyleCategories("avataaars");
    const keys = cats.map((c) => c.key);
    expect(cats.length).toBeGreaterThan(0);
    expect(keys).toContain("eyes");
    expect(keys).toContain("mouth");
    // every category has a non-empty list of string values and a label
    for (const c of cats) {
      expect(c.values.length).toBeGreaterThan(0);
      expect(typeof c.label).toBe("string");
      expect(c.label.length).toBeGreaterThan(0);
    }
  });

  it("returns an array (never throws) for a geometric style", () => {
    expect(Array.isArray(getStyleCategories("identicon"))).toBe(true);
  });

  it("returns [] for an unknown style", () => {
    expect(getStyleCategories("nope")).toEqual([]);
  });
```

Also update the import line at the top of the test file to include `getStyleCategories`:

```ts
import {
  AVATAR_STYLES,
  renderAvatarDataUri,
  randomSeed,
  getStyleCategories,
} from "@/features/profile/avatar";
```

- [ ] **Step 2: Run tests to verify they fail**

Run from `suspicious-ui/`:
```bash
CI=true pnpm test src/features/profile/__tests__/avatar.test.ts
```
Expected: FAIL — `getStyleCategories` is not exported; options render assertions fail.

- [ ] **Step 3: Extend `AvatarConfig` and `renderAvatarDataUri`**

In `suspicious-ui/src/features/profile/avatar.ts`, replace the `AvatarConfig` type (line 13) and the `renderAvatarDataUri` function (lines 34-44) with:

```ts
export type AvatarConfig = {
  style: string;
  seed: string;
  options?: Record<string, string[]>;
};
```

```ts
export function renderAvatarDataUri(config: AvatarConfig): string {
  const style = STYLE_MAP.get(config.style);
  if (!style) return "";
  const options = config.options ?? {};
  const cacheKey = `${config.style}|${config.seed}|${JSON.stringify(options)}`;
  const hit = cache.get(cacheKey);
  if (hit !== undefined) return hit;
  // @dicebear/core v9: toDataUri() is synchronous and returns a string.
  // DiceBear option values are arrays; a single-element array pins a choice.
  const uri = createAvatar(style as never, { seed: config.seed, ...options }).toDataUri();
  cache.set(cacheKey, uri);
  return uri;
}
```

- [ ] **Step 4: Add `getStyleCategories`**

In the same file, add below `renderAvatarDataUri` (and above `randomSeed`):

```ts
// A category is any style-schema property that is an enum array of strings
// (e.g. avataaars `eyes`, `mouth`, enum `*Color`). Numeric `*Probability`
// props and free-form (non-enum) props are skipped. Schemas are static, so
// the derived list is memoized per style.
const categoryCache = new Map<string, { key: string; label: string; values: string[] }[]>();

function prettifyLabel(key: string): string {
  return key
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (c) => c.toUpperCase())
    .trim();
}

export function getStyleCategories(
  styleKey: string,
): { key: string; label: string; values: string[] }[] {
  const hit = categoryCache.get(styleKey);
  if (hit) return hit;
  const style = STYLE_MAP.get(styleKey) as unknown as
    | { schema?: { properties?: Record<string, unknown> } }
    | undefined;
  const props = style?.schema?.properties ?? {};
  const cats: { key: string; label: string; values: string[] }[] = [];
  for (const [key, raw] of Object.entries(props)) {
    const p = raw as { type?: string; items?: { enum?: unknown[] } };
    const en = p?.items?.enum;
    if (
      p?.type === "array" &&
      Array.isArray(en) &&
      en.length > 0 &&
      en.every((v) => typeof v === "string")
    ) {
      cats.push({ key, label: prettifyLabel(key), values: en as string[] });
    }
  }
  categoryCache.set(styleKey, cats);
  return cats;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run:
```bash
CI=true pnpm test src/features/profile/__tests__/avatar.test.ts
```
Expected: PASS (original cases + 5 new).

- [ ] **Step 6: Commit**

```bash
git add suspicious-ui/src/features/profile/avatar.ts suspicious-ui/src/features/profile/__tests__/avatar.test.ts
git commit -m "feat(ui): render dicebear options and extract style categories"
```

---

### Task 2: Backend — accept and bound-validate `avatar.options`

**Files:**
- Modify: `Suspicious/Suspicious/api/serializers/profile.py`
- Modify: `Suspicious/Suspicious/api/tests/test_profile_avatar.py`

**Interfaces:**
- Consumes: existing `AvatarField`, `ALLOWED_AVATAR_STYLES`; existing `PATCH /api/profile/appearance/`.
- Produces: `AvatarField` now returns `{style, seed}` or `{style, seed, options}` where `options` is a validated `dict[str, list[str]]`.

- [ ] **Step 1: Write the failing tests**

Append to `Suspicious/Suspicious/api/tests/test_profile_avatar.py` (inside the existing `AvatarAppearanceTests` class):

```python
    def test_valid_options_saves_and_roundtrips(self):
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123",
                        "options": {"eyes": ["happy"]}}},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(
            resp.data["avatar"],
            {"style": "avataaars", "seed": "abc123", "options": {"eyes": ["happy"]}},
        )
        get = self.client.get("/api/profile/")
        self.assertEqual(get.data["avatar"]["options"], {"eyes": ["happy"]})

    def test_string_option_value_is_normalised_to_list(self):
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123",
                        "options": {"eyes": "happy"}}},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["avatar"]["options"], {"eyes": ["happy"]})

    def test_too_many_option_keys_rejected(self):
        opts = {f"k{i}": ["v"] for i in range(21)}
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123", "options": opts}},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_oversized_option_value_rejected(self):
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123",
                        "options": {"eyes": ["z" * 65]}}},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_non_string_option_value_rejected(self):
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123",
                        "options": {"eyes": [42]}}},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_empty_options_are_dropped(self):
        resp = self.client.patch(
            self.url,
            {"avatar": {"style": "avataaars", "seed": "abc123", "options": {}}},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["avatar"], {"style": "avataaars", "seed": "abc123"})
```

- [ ] **Step 2: Run tests to verify they fail**

Run from `Suspicious/Suspicious/`:
```bash
python manage.py test api.tests.test_profile_avatar -v 2
```
Expected: FAIL — options round-trip returns `{style, seed}` without options; oversized cases return 200 instead of 400.

- [ ] **Step 3: Add the options caps + validator**

In `Suspicious/Suspicious/api/serializers/profile.py`, after the `ALLOWED_AVATAR_STYLES` set (after line 83, before `class AvatarField`), add:

```python
MAX_AVATAR_OPTION_KEYS = 20
MAX_AVATAR_OPTION_KEY_LEN = 32
MAX_AVATAR_OPTION_VALUE_LEN = 64
MAX_AVATAR_OPTION_LIST_ITEMS = 20
MAX_AVATAR_OPTIONS_BYTES = 2048


def _validate_avatar_options(options):
    """Bounded/loose validation of the DiceBear options blob.

    Accepts a dict of category -> (str | list[str]); normalises scalars to
    one-element lists. Enforces size caps only; DiceBear ignores unknown
    keys and the avatar renders solely in the owner's browser, so caps are
    the only real safeguard needed.
    """
    import json

    if not isinstance(options, dict):
        raise serializers.ValidationError("avatar.options must be an object.")
    if len(options) > MAX_AVATAR_OPTION_KEYS:
        raise serializers.ValidationError(
            f"avatar.options may have at most {MAX_AVATAR_OPTION_KEYS} keys."
        )
    clean = {}
    for key, value in options.items():
        if not isinstance(key, str) or not (1 <= len(key) <= MAX_AVATAR_OPTION_KEY_LEN):
            raise serializers.ValidationError(
                f"avatar.options key must be a string of length "
                f"1..{MAX_AVATAR_OPTION_KEY_LEN}. Got: {key!r}"
            )
        if isinstance(value, str):
            items = [value]
        elif isinstance(value, list):
            items = value
        else:
            raise serializers.ValidationError(
                f"avatar.options.{key} must be a string or list of strings."
            )
        if len(items) > MAX_AVATAR_OPTION_LIST_ITEMS:
            raise serializers.ValidationError(
                f"avatar.options.{key} may have at most "
                f"{MAX_AVATAR_OPTION_LIST_ITEMS} items."
            )
        for item in items:
            if not isinstance(item, str) or not (1 <= len(item) <= MAX_AVATAR_OPTION_VALUE_LEN):
                raise serializers.ValidationError(
                    f"avatar.options.{key} values must be strings of length "
                    f"1..{MAX_AVATAR_OPTION_VALUE_LEN}."
                )
        clean[key] = items
    if len(json.dumps(clean)) > MAX_AVATAR_OPTIONS_BYTES:
        raise serializers.ValidationError(
            f"avatar.options is too large (max {MAX_AVATAR_OPTIONS_BYTES} bytes)."
        )
    return clean
```

- [ ] **Step 4: Wire options into `AvatarField.to_internal_value`**

In the same file, replace the final `return {"style": style, "seed": seed}` inside `AvatarField.to_internal_value` (line 110) with:

```python
        result = {"style": style, "seed": seed}
        options = data.get("options")
        if options:
            result["options"] = _validate_avatar_options(options)
        return result
```

(An empty/absent `options` is dropped — matching the `test_empty_options_are_dropped` case. `not data` already handles the whole-avatar clear at the top of the method.)

- [ ] **Step 5: Run tests to verify they pass**

Run:
```bash
python manage.py test api.tests.test_profile_avatar -v 2
```
Expected: PASS (all prior cases + 6 new). If the local env lacks DB access, run inside the container: `cd deployment && make shell` then the same command.

- [ ] **Step 6: Commit**

```bash
git add Suspicious/Suspicious/api/serializers/profile.py Suspicious/Suspicious/api/tests/test_profile_avatar.py
git commit -m "feat(api): accept bounded avatar.options on appearance endpoint"
```

---

### Task 3: AvatarPanel — per-category carousels

**Files:**
- Modify: `suspicious-ui/src/features/profile/AvatarPanel.tsx`
- Create: `suspicious-ui/src/features/profile/__tests__/AvatarPanel.test.tsx`

**Interfaces:**
- Consumes: `getStyleCategories`, `renderAvatarDataUri`, `AvatarConfig` (Task 1); `AVATAR_STYLES`, `UserAvatar`, `CaptionLabel`, `InnerCard`.
- Produces: `AvatarPanel` gains two props — `options: Record<string, string[]>` and `setOptions: (o: Record<string, string[]>) => void`. Carousel buttons expose aria-labels `"<Label> previous option"`, `"<Label> next option"`, `"<Label> use random"`.

- [ ] **Step 1: Write the failing test**

Create `suspicious-ui/src/features/profile/__tests__/AvatarPanel.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AvatarPanel } from "@/features/profile/AvatarPanel";
import { getStyleCategories } from "@/features/profile/avatar";

function renderPanel(options: Record<string, string[]>, setOptions = vi.fn()) {
  render(
    <AvatarPanel
      style="avataaars"
      seed="abc123"
      setStyle={vi.fn()}
      setSeed={vi.fn()}
      options={options}
      setOptions={setOptions}
      firstName="Al"
      lastName="Ice"
      dirtyBar={null}
    />,
  );
  return setOptions;
}

describe("AvatarPanel categories", () => {
  it("pins the first value of a category when Next is clicked from Auto", async () => {
    const eyes = getStyleCategories("avataaars").find((c) => c.key === "eyes")!;
    const setOptions = renderPanel({});
    await userEvent.click(screen.getByLabelText("Eyes next option"));
    expect(setOptions).toHaveBeenCalledWith({ eyes: [eyes.values[0]] });
  });

  it("clears a pinned category back to random", async () => {
    const eyes = getStyleCategories("avataaars").find((c) => c.key === "eyes")!;
    const setOptions = renderPanel({ eyes: [eyes.values[1]] });
    await userEvent.click(screen.getByLabelText("Eyes use random"));
    expect(setOptions).toHaveBeenCalledWith({});
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run from `suspicious-ui/`:
```bash
CI=true pnpm test src/features/profile/__tests__/AvatarPanel.test.tsx
```
Expected: FAIL — `AvatarPanel` has no `options`/`setOptions` props; the labelled buttons don't exist.

- [ ] **Step 3: Add the props and Categories section**

In `suspicious-ui/src/features/profile/AvatarPanel.tsx`:

Replace the import block (lines 1-12) with (adds `getStyleCategories` and the `CasinoOutlined`/`RestartAltOutlined` icons):

```tsx
import * as React from "react";
import { Box, Button, Divider, IconButton, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  PersonOutlined,
  CasinoOutlined,
  ChevronLeft,
  ChevronRight,
  RestartAltOutlined,
} from "@mui/icons-material";
import { CaptionLabel, InnerCard } from "@/features/profile/components/cards";
import { UserAvatar } from "@/features/profile/components/UserAvatar";
import {
  AVATAR_STYLES,
  getStyleCategories,
  renderAvatarDataUri,
  type AvatarConfig,
} from "@/features/profile/avatar";
import { initials as initialsFn } from "@/features/profile/utils";
```

Replace the component signature (lines 15-27) with (adds `options`/`setOptions`, and threads them into the preview `config`):

```tsx
// DirtyBar lives in ProfilePage; the panel is controlled and the parent renders it.
export function AvatarPanel({
  style, seed, setStyle, setSeed,
  options, setOptions,
  firstName, lastName,
  dirtyBar,
}: {
  style: string; seed: string;
  setStyle: (s: string) => void; setSeed: (s: string) => void;
  options: Record<string, string[]>;
  setOptions: (o: Record<string, string[]>) => void;
  firstName?: string; lastName?: string;
  dirtyBar: React.ReactNode;
}) {
  const theme = useTheme();
  const config: AvatarConfig = { style, seed, options };
  const inits = initialsFn(firstName, lastName);
  const categories = getStyleCategories(style);
```

Then, immediately before the closing `</Stack>` of the component (currently line 95-96, after the Style grid `</Stack>` block), insert the Categories section:

```tsx
      {/* Categories — one carousel per enum option in the style's schema */}
      {categories.length > 0 && (
        <Stack spacing={1}>
          <CaptionLabel>Customize</CaptionLabel>
          <Stack spacing={0.5} sx={{ maxHeight: 320, overflowY: "auto", pr: 0.5 }}>
            {categories.map((cat) => {
              const current = options[cat.key]?.[0];
              const idx = current ? cat.values.indexOf(current) : -1;
              const move = (dir: 1 | -1) => {
                const base = idx < 0 ? (dir === 1 ? -1 : 0) : idx;
                const next = (base + dir + cat.values.length) % cat.values.length;
                setOptions({ ...options, [cat.key]: [cat.values[next]] });
              };
              const clear = () => {
                const rest = { ...options };
                delete rest[cat.key];
                setOptions(rest);
              };
              return (
                <Stack
                  key={cat.key}
                  direction="row"
                  spacing={1}
                  sx={{
                    alignItems: "center",
                    px: 1, py: 0.5, borderRadius: 2,
                    border: `1px solid ${alpha(theme.palette.divider, 0.4)}`,
                  }}
                >
                  <Typography sx={{ flex: 1, minWidth: 0, fontWeight: 800, fontSize: 12.5 }} noWrap>
                    {cat.label}
                  </Typography>
                  <IconButton size="small" aria-label={`${cat.label} previous option`} onClick={() => move(-1)}>
                    <ChevronLeft fontSize="small" />
                  </IconButton>
                  <Typography
                    sx={{ width: 96, textAlign: "center", fontSize: 11.5,
                          color: current ? "text.primary" : "text.disabled",
                          fontWeight: current ? 800 : 600 }}
                    noWrap
                  >
                    {current ?? "Auto"}
                  </Typography>
                  <IconButton size="small" aria-label={`${cat.label} next option`} onClick={() => move(1)}>
                    <ChevronRight fontSize="small" />
                  </IconButton>
                  <IconButton
                    size="small"
                    aria-label={`${cat.label} use random`}
                    onClick={clear}
                    disabled={!current}
                    sx={{ opacity: current ? 1 : 0.35 }}
                  >
                    <RestartAltOutlined fontSize="small" />
                  </IconButton>
                </Stack>
              );
            })}
          </Stack>
        </Stack>
      )}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
CI=true pnpm test src/features/profile/__tests__/AvatarPanel.test.tsx
```
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add suspicious-ui/src/features/profile/AvatarPanel.tsx suspicious-ui/src/features/profile/__tests__/AvatarPanel.test.tsx
git commit -m "feat(ui): per-category avatar carousels in AvatarPanel"
```

---

### Task 4: ProfilePage — options state, dirty, save, reset

**Files:**
- Modify: `suspicious-ui/src/pages/ProfilePage.tsx`

**Interfaces:**
- Consumes: `AvatarPanel` `options`/`setOptions` props (Task 3); existing `avatarStyle`/`avatarSeed` state, `appearanceMutation`, `queryClient`, `baseProfile`, `DirtyBar`.
- Produces: no new exports; wires `avatarOptions` end-to-end.

- [ ] **Step 1: Add the options state and sync**

In `suspicious-ui/src/pages/ProfilePage.tsx`, after the `avatarSeed` state (line 439) add:

```tsx
  const [avatarOptions, setAvatarOptions] =
    React.useState<Record<string, string[]>>({});
```

In the profile-sync block, after `setAvatarSeed(profileData.avatar?.seed ?? "");` (line 459) add:

```tsx
      setAvatarOptions(profileData.avatar?.options ?? {});
```

- [ ] **Step 2: Include options in dirty detection**

Replace the `avatarDirty` block (lines 531-533) with:

```tsx
  const avatarDirty =
    avatarStyle !== (baseProfile?.avatar?.style ?? "") ||
    avatarSeed  !== (baseProfile?.avatar?.seed  ?? "") ||
    JSON.stringify(avatarOptions) !==
      JSON.stringify(baseProfile?.avatar?.options ?? {});
```

- [ ] **Step 3: Include options in save + reset**

Replace `saveAvatar` and `resetAvatar` (lines 568-580) with:

```tsx
  function saveAvatar() {
    const hasOptions = Object.keys(avatarOptions).length > 0;
    const avatar =
      avatarStyle && avatarSeed
        ? { style: avatarStyle, seed: avatarSeed, ...(hasOptions ? { options: avatarOptions } : {}) }
        : {};
    queryClient.setQueryData<UserProfile>(["profile"], (prev) => ({
      ...(prev ?? baseProfile as UserProfile),
      avatar: avatar as UserProfile["avatar"],
    }));
    appearanceMutation.mutate({ avatar: avatar as any });
  }

  function resetAvatar() {
    setAvatarStyle(baseProfile?.avatar?.style ?? "");
    setAvatarSeed(baseProfile?.avatar?.seed ?? "");
    setAvatarOptions(baseProfile?.avatar?.options ?? {});
  }
```

- [ ] **Step 4: Pass options through to the panel**

Replace the `<AvatarPanel … />` block (lines 858-869) with:

```tsx
              <AvatarPanel
                style={avatarStyle} seed={avatarSeed}
                setStyle={setStyleWithSeed} setSeed={setAvatarSeed}
                options={avatarOptions} setOptions={setAvatarOptions}
                firstName={me.first_name} lastName={me.last_name}
                dirtyBar={
                  <DirtyBar
                    dirty={avatarDirty} saving={appearanceMutation.isPending}
                    onSave={saveAvatar} onReset={resetAvatar}
                    label="Unsaved avatar changes"
                  />
                }
              />
```

- [ ] **Step 5: Verify `UserProfile.avatar` type carries options**

Confirm `suspicious-ui/src/features/profile/api.ts` types `avatar` as `AvatarConfig` (it imports `AvatarConfig` from `@/features/profile/avatar`). Since Task 1 added `options?` to `AvatarConfig`, no change is needed here. Grep to confirm:

```bash
grep -n "avatar?" suspicious-ui/src/features/profile/api.ts
```
Expected: `avatar?:               AvatarConfig;` — already correct.

- [ ] **Step 6: Run the full frontend suite + typecheck**

Run from `suspicious-ui/`:
```bash
CI=true pnpm test src/features/profile
npx tsc --noEmit
```
Expected: all profile tests pass; `tsc` exits 0.

- [ ] **Step 7: Manual smoke (optional but recommended)**

`pnpm dev`, log in, Profile → Avatar. Pick "Avataaars", scroll to Customize, advance a couple of categories (e.g. Eyes, Mouth), confirm the live preview + hero update. Click a category's random-reset and confirm it reverts to seed-driven. Save, reload, confirm persistence. Randomize and confirm pinned categories stay while others change.

- [ ] **Step 8: Commit**

```bash
git add suspicious-ui/src/pages/ProfilePage.tsx
git commit -m "feat(ui): persist per-category avatar options from profile page"
```

---

## Self-Review

**Spec coverage:**
- Config shape `{style, seed, options}` → Task 1 (`AvatarConfig`), Task 2 (backend), Task 4 (persist). ✓
- Schema-driven categories, enum-only, skip `*Probability`/non-enum → Task 1 `getStyleCategories`. ✓
- Render honors options; memo key includes options → Task 1. ✓
- Seed stays base; Randomize rerolls seed only, never options → Task 3 (Randomize button untouched), Task 4 (save keeps options). ✓
- Per-category carousels with pin + "Auto"/clear; scrollable; re-derive on style change → Task 3. ✓
- Backend bounded/loose caps (20 keys / 32 key / 64 value / 20 items / 2KB), string→list normalise, no schema cross-check, empty dropped → Task 2. ✓
- No migration (JSONField already) → stated in header; Task 2 touches serializer only. ✓
- Backward compat (`{style, seed}` unchanged, `{}` clears) → Task 1 Step 3 test, Task 2 `not data` path + `test_empty_options_are_dropped`. ✓
- Tests: deterministic-with-options, backward-compat guard, category extraction, panel pin/clear, backend accept/reject → Tasks 1, 2, 3. ✓
- Out of scope (probability/free-form color, bg/flip, upload, strict validation) → excluded. ✓

**Placeholder scan:** No TBD/TODO; every code step shows full code. ✓

**Type consistency:** `AvatarConfig` (Task 1) with `options?: Record<string,string[]>` consumed identically by `renderAvatarDataUri` (Task 1), `AvatarPanel` props (Task 3), and ProfilePage `avatarOptions` (Task 4). `getStyleCategories` return shape `{key,label,values}` used in AvatarPanel map and both tests. Backend `options` `dict[str,list[str]]` matches the frontend `Record<string,string[]>`. Carousel aria-labels defined in Task 3 match those queried in the Task 3 test. ✓
