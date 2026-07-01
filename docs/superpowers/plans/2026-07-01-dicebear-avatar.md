# DiceBear Avatar Customization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user pick a DiceBear avatar (style + randomizable seed) that renders everywhere they appear, falling back to initials.

**Architecture:** Store a tiny `{style, seed}` JSON blob on the profile (new `avatar` JSONField, same pattern as `semantic_colors`). Reuse the existing `PATCH /api/profile/appearance/` endpoint to save it. On the frontend, bundle `@dicebear/core` + `@dicebear/collection`, render SVG data URIs client-side, expose a picker panel in ProfilePage, and share one `UserAvatar` component between the profile hero and the sidebar chip.

**Tech Stack:** Django REST Framework, React 19 + TypeScript + MUI v9, TanStack Query v5, Vitest, `@dicebear/core` + `@dicebear/collection` (v9).

## Global Constraints

- DiceBear renders **client-side only** — no calls to `api.dicebear.com`. Use the bundled library.
- Stored avatar config shape is exactly `{ "style": string, "seed": string }`, or `{}` for "no custom avatar".
- Allowed styles (backend allowlist AND frontend list, kept in sync by hand): `bottts`, `identicon`, `initials`, `avataaars`, `funEmoji`, `thumbs`, `shapes`, `notionists`.
- `seed` is a string, length 1..64.
- Empty config `{}` = fall back to initials.
- Conventional Commits for messages.
- Frontend tests: `pnpm test` from `suspicious-ui/`. Backend tests: `python manage.py test <path>` from `Suspicious/Suspicious/` (or inside the web container via `make shell` if the local env lacks DB access).

---

### Task 1: Add `avatar` field to profile models + migration

**Files:**
- Modify: `Suspicious/Suspicious/profiles/models.py` (UserProfile ~line 80-107, CISOProfile ~line 109-137)
- Create: `Suspicious/Suspicious/profiles/migrations/0009_userprofile_avatar_cisoprofile_avatar.py` (via makemigrations)

**Interfaces:**
- Produces: `UserProfile.avatar` and `CISOProfile.avatar` — `JSONField(default=dict, blank=True)`.

- [ ] **Step 1: Add the field to both models**

In `UserProfile`, after the `semantic_colors` field (before `creation_date`):

```python
    avatar = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_("Avatar"),
        help_text=_(
            "DiceBear avatar config. Structure: {style: '<dicebear-style>', "
            "seed: '<string>'}. Empty means fall back to initials."
        ),
    )
```

Add the identical field to `CISOProfile` in the same position (after its `semantic_colors`, before `creation_date`).

- [ ] **Step 2: Generate the migration**

Run from `Suspicious/Suspicious/`:
```bash
python manage.py makemigrations profiles
```
Expected: creates `0009_userprofile_avatar_cisoprofile_avatar.py` adding `avatar` to both models. (If local DB/env is unavailable, run inside the container: `cd deployment && make shell` then `python manage.py makemigrations profiles`.)

- [ ] **Step 3: Verify the migration applies**

Run:
```bash
python manage.py migrate profiles
```
Expected: `Applying profiles.0009_... OK`.

- [ ] **Step 4: Commit**

```bash
git add Suspicious/Suspicious/profiles/models.py Suspicious/Suspicious/profiles/migrations/0009_*.py
git commit -m "feat(profiles): add avatar JSONField to user and CISO profiles"
```

---

### Task 2: Backend avatar validation + serializer wiring

**Files:**
- Modify: `Suspicious/Suspicious/api/serializers/profile.py`
- Create: `Suspicious/Suspicious/api/tests/test_profile_avatar.py`

**Interfaces:**
- Consumes: `UserProfile.avatar`, `CISOProfile.avatar` (Task 1); existing `AppearanceView` at `PATCH /api/profile/appearance/`; existing `_get_profile` helper.
- Produces: `ALLOWED_AVATAR_STYLES: set[str]`, `AvatarField(serializers.JSONField)`. `avatar` added to `UserProfileSerializer`/`CISOProfileSerializer` fields and to `AppearanceSerializer`.

- [ ] **Step 1: Write the failing tests**

Create `Suspicious/Suspicious/api/tests/test_profile_avatar.py`:

```python
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token  # noqa: F401 (import style parity)

User = get_user_model()


class AvatarAppearanceTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw12345!")
        self.client.force_authenticate(user=self.user)
        self.url = "/api/profile/appearance/"

    def test_valid_avatar_saves_and_roundtrips(self):
        resp = self.client.patch(
            self.url, {"avatar": {"style": "bottts", "seed": "abc123"}}, format="json"
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["avatar"], {"style": "bottts", "seed": "abc123"})

        get = self.client.get("/api/profile/")
        self.assertEqual(get.data["avatar"], {"style": "bottts", "seed": "abc123"})

    def test_unknown_style_rejected(self):
        resp = self.client.patch(
            self.url, {"avatar": {"style": "not-a-style", "seed": "x"}}, format="json"
        )
        self.assertEqual(resp.status_code, 400)

    def test_oversized_seed_rejected(self):
        resp = self.client.patch(
            self.url, {"avatar": {"style": "bottts", "seed": "z" * 65}}, format="json"
        )
        self.assertEqual(resp.status_code, 400)

    def test_non_string_seed_rejected(self):
        resp = self.client.patch(
            self.url, {"avatar": {"style": "bottts", "seed": 42}}, format="json"
        )
        self.assertEqual(resp.status_code, 400)

    def test_empty_object_clears_avatar(self):
        self.client.patch(
            self.url, {"avatar": {"style": "bottts", "seed": "abc123"}}, format="json"
        )
        resp = self.client.patch(self.url, {"avatar": {}}, format="json")
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["avatar"], {})
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
python manage.py test api.tests.test_profile_avatar -v 2
```
Expected: FAIL — `avatar` not accepted / not in response.

- [ ] **Step 3: Add the allowlist + AvatarField**

In `Suspicious/Suspicious/api/serializers/profile.py`, after the `SemanticColorsField` class (before the "Profile serializers" section), add:

```python
# ---------------------------------------------------------------------------
# Avatar field
#
# Validates DiceBear avatar config: {style, seed} or {} to clear.
# Kept in sync by hand with suspicious-ui AVATAR_STYLES.
# ---------------------------------------------------------------------------

ALLOWED_AVATAR_STYLES = {
    "bottts", "identicon", "initials", "avataaars",
    "funEmoji", "thumbs", "shapes", "notionists",
}


class AvatarField(serializers.JSONField):
    """Validates a DiceBear avatar config: {} or {style, seed}."""

    def to_internal_value(self, data):
        data = super().to_internal_value(data)

        if not isinstance(data, dict):
            raise serializers.ValidationError("avatar must be an object.")

        if not data:
            return {}

        style = data.get("style")
        seed = data.get("seed")

        if style not in ALLOWED_AVATAR_STYLES:
            raise serializers.ValidationError(
                f"avatar.style must be one of {sorted(ALLOWED_AVATAR_STYLES)}. Got: {style!r}"
            )
        if not isinstance(seed, str) or not (1 <= len(seed) <= 64):
            raise serializers.ValidationError(
                "avatar.seed must be a string of length 1..64."
            )

        return {"style": style, "seed": seed}
```

- [ ] **Step 4: Add `avatar` to the read serializers**

Add `"avatar",` to `UserProfileSerializer.Meta.fields` and `CISOProfileSerializer.Meta.fields` (place it right after `"semantic_colors",`). No change to `read_only_fields`.

- [ ] **Step 5: Add `avatar` to AppearanceSerializer**

In `AppearanceSerializer`, after the `semantic_colors` field declaration:

```python
    avatar = AvatarField(required=False)
```
(The existing `update()` loops over `validated_data.items()` and `save(update_fields=...)`, so `avatar` is persisted with no further change.)

- [ ] **Step 6: Run tests to verify they pass**

Run:
```bash
python manage.py test api.tests.test_profile_avatar -v 2
```
Expected: PASS (5 tests).

- [ ] **Step 7: Commit**

```bash
git add Suspicious/Suspicious/api/serializers/profile.py Suspicious/Suspicious/api/tests/test_profile_avatar.py
git commit -m "feat(api): validate and expose avatar on profile appearance endpoint"
```

---

### Task 3: Install DiceBear + avatar render helper

**Files:**
- Modify: `suspicious-ui/package.json` (dependencies)
- Create: `suspicious-ui/src/features/profile/avatar.ts`
- Create: `suspicious-ui/src/features/profile/__tests__/avatar.test.ts`

**Interfaces:**
- Produces:
  - `type AvatarConfig = { style: string; seed: string }`
  - `AVATAR_STYLES: { key: string; label: string; style: unknown }[]` (`style` is the DiceBear collection style object)
  - `renderAvatarDataUri(config: AvatarConfig): string`
  - `randomSeed(): string`

- [ ] **Step 1: Install the dependencies**

Run from `suspicious-ui/`:
```bash
pnpm add @dicebear/core @dicebear/collection
```
Expected: both added to `dependencies` in `package.json`.

- [ ] **Step 2: Write the failing test**

Create `suspicious-ui/src/features/profile/__tests__/avatar.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import {
  AVATAR_STYLES,
  renderAvatarDataUri,
  randomSeed,
} from "@/features/profile/avatar";

describe("avatar helper", () => {
  it("exposes the agreed style allowlist", () => {
    const keys = AVATAR_STYLES.map((s) => s.key).sort();
    expect(keys).toEqual(
      ["avataaars", "bottts", "funEmoji", "identicon", "initials", "notionists", "shapes", "thumbs"],
    );
  });

  it("renders a deterministic svg data uri", () => {
    const a = renderAvatarDataUri({ style: "bottts", seed: "abc123" });
    const b = renderAvatarDataUri({ style: "bottts", seed: "abc123" });
    expect(a).toBe(b);
    expect(a.startsWith("data:image/svg+xml")).toBe(true);
  });

  it("produces different output for different seeds", () => {
    const a = renderAvatarDataUri({ style: "bottts", seed: "abc123" });
    const b = renderAvatarDataUri({ style: "bottts", seed: "zzz999" });
    expect(a).not.toBe(b);
  });

  it("falls back safely on unknown style", () => {
    const uri = renderAvatarDataUri({ style: "nope", seed: "x" });
    expect(uri).toBe("");
  });

  it("randomSeed returns a non-empty short string", () => {
    const s = randomSeed();
    expect(typeof s).toBe("string");
    expect(s.length).toBeGreaterThan(0);
    expect(s.length).toBeLessThanOrEqual(64);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run:
```bash
pnpm test -- src/features/profile/__tests__/avatar.test.ts
```
Expected: FAIL — module `@/features/profile/avatar` not found.

- [ ] **Step 4: Write the helper**

Create `suspicious-ui/src/features/profile/avatar.ts`:

```ts
import { createAvatar } from "@dicebear/core";
import {
  bottts,
  identicon,
  initials,
  avataaars,
  funEmoji,
  thumbs,
  shapes,
  notionists,
} from "@dicebear/collection";

export type AvatarConfig = { style: string; seed: string };

// Allowlist — MUST stay in sync with ALLOWED_AVATAR_STYLES in
// Suspicious/api/serializers/profile.py.
export const AVATAR_STYLES = [
  { key: "bottts", label: "Bottts", style: bottts },
  { key: "identicon", label: "Identicon", style: identicon },
  { key: "initials", label: "Initials", style: initials },
  { key: "avataaars", label: "Avataaars", style: avataaars },
  { key: "funEmoji", label: "Fun Emoji", style: funEmoji },
  { key: "thumbs", label: "Thumbs", style: thumbs },
  { key: "shapes", label: "Shapes", style: shapes },
  { key: "notionists", label: "Notionists", style: notionists },
] as const;

const STYLE_MAP = new Map(AVATAR_STYLES.map((s) => [s.key, s.style]));

const cache = new Map<string, string>();

export function renderAvatarDataUri(config: AvatarConfig): string {
  const style = STYLE_MAP.get(config.style);
  if (!style) return "";
  const cacheKey = `${config.style}|${config.seed}`;
  const hit = cache.get(cacheKey);
  if (hit !== undefined) return hit;
  // @dicebear/core v9: toDataUri() is synchronous and returns a string.
  const uri = createAvatar(style as never, { seed: config.seed }).toDataUri();
  cache.set(cacheKey, uri);
  return uri;
}

export function randomSeed(): string {
  return Math.random().toString(36).slice(2, 12);
}
```

- [ ] **Step 5: Run test to verify it passes**

Run:
```bash
pnpm test -- src/features/profile/__tests__/avatar.test.ts
```
Expected: PASS (5 tests). If `toDataUri()` output is not a string in this jsdom env, confirm `@dicebear/core` v9 — its `toDataUri()` is synchronous; do not `await` it.

- [ ] **Step 6: Commit**

```bash
git add suspicious-ui/package.json suspicious-ui/pnpm-lock.yaml suspicious-ui/src/features/profile/avatar.ts suspicious-ui/src/features/profile/__tests__/avatar.test.ts
git commit -m "feat(ui): bundle dicebear and add avatar render helper"
```

---

### Task 4: Shared `UserAvatar` component

**Files:**
- Create: `suspicious-ui/src/features/profile/components/UserAvatar.tsx`
- Create: `suspicious-ui/src/features/profile/__tests__/UserAvatar.test.tsx`

**Interfaces:**
- Consumes: `AvatarConfig`, `renderAvatarDataUri` (Task 3).
- Produces: `UserAvatar` React component —
  `{ avatar?: AvatarConfig | null; initials: string; sx?: SxProps<Theme> }` (extra MUI `Avatar` props passthrough).

- [ ] **Step 1: Write the failing test**

Create `suspicious-ui/src/features/profile/__tests__/UserAvatar.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { UserAvatar } from "@/features/profile/components/UserAvatar";

describe("UserAvatar", () => {
  it("renders an img when avatar config is set", () => {
    render(<UserAvatar avatar={{ style: "bottts", seed: "abc123" }} initials="AB" />);
    const img = screen.getByRole("img");
    expect(img.getAttribute("src")).toMatch(/^data:image\/svg\+xml/);
  });

  it("renders initials when no avatar", () => {
    render(<UserAvatar avatar={null} initials="AB" />);
    expect(screen.getByText("AB")).toBeInTheDocument();
  });

  it("renders initials when avatar has empty style", () => {
    render(<UserAvatar avatar={{ style: "", seed: "" }} initials="CD" />);
    expect(screen.getByText("CD")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
pnpm test -- src/features/profile/__tests__/UserAvatar.test.tsx
```
Expected: FAIL — component not found.

- [ ] **Step 3: Write the component**

Create `suspicious-ui/src/features/profile/components/UserAvatar.tsx`:

```tsx
import { Avatar } from "@mui/material";
import type { SxProps, Theme } from "@mui/material/styles";
import { renderAvatarDataUri, type AvatarConfig } from "@/features/profile/avatar";

export function UserAvatar({
  avatar,
  initials,
  sx,
  ...rest
}: {
  avatar?: AvatarConfig | null;
  initials: string;
  sx?: SxProps<Theme>;
} & Record<string, unknown>) {
  const src =
    avatar?.style && avatar?.seed ? renderAvatarDataUri(avatar) : "";

  if (src) {
    return <Avatar src={src} alt={initials} sx={sx} {...rest} />;
  }
  return <Avatar sx={sx} {...rest}>{initials}</Avatar>;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
pnpm test -- src/features/profile/__tests__/UserAvatar.test.tsx
```
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add suspicious-ui/src/features/profile/components/UserAvatar.tsx suspicious-ui/src/features/profile/__tests__/UserAvatar.test.tsx
git commit -m "feat(ui): shared UserAvatar component with initials fallback"
```

---

### Task 5: Avatar picker panel + ProfilePage wiring

**Files:**
- Modify: `suspicious-ui/src/features/profile/api.ts` (types)
- Create: `suspicious-ui/src/features/profile/AvatarPanel.tsx`
- Modify: `suspicious-ui/src/pages/ProfilePage.tsx`

**Interfaces:**
- Consumes: `AvatarConfig`, `AVATAR_STYLES`, `renderAvatarDataUri`, `randomSeed` (Task 3); `UserAvatar` (Task 4); existing `updateAppearance`, `DirtyBar`, `InnerCard`, `CaptionLabel`, `initials`.
- Produces: `AvatarPanel` component; `avatar?: AvatarConfig` added to `UserProfile` and `AppearancePayload`.

- [ ] **Step 1: Extend the API types**

In `suspicious-ui/src/features/profile/api.ts`:
- Add an import at the top: `import type { AvatarConfig } from "@/features/profile/avatar";`
- Add `avatar?: AvatarConfig;` to the `UserProfile` type (after `auto_seasonal`).
- Add `avatar?: AvatarConfig;` to the `AppearancePayload` type.

- [ ] **Step 2: Write the AvatarPanel**

Create `suspicious-ui/src/features/profile/AvatarPanel.tsx`:

```tsx
import * as React from "react";
import { Box, Button, Divider, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { PersonOutlined, CasinoOutlined } from "@mui/icons-material";
import { CaptionLabel, InnerCard } from "@/features/profile/components/cards";
import { UserAvatar } from "@/features/profile/components/UserAvatar";
import {
  AVATAR_STYLES,
  renderAvatarDataUri,
  type AvatarConfig,
} from "@/features/profile/avatar";
import { initials as initialsFn } from "@/features/profile/utils";

// DirtyBar lives in ProfilePage; the panel is controlled and the parent renders it.
export function AvatarPanel({
  style, seed, setStyle, setSeed,
  firstName, lastName,
  dirtyBar,
}: {
  style: string; seed: string;
  setStyle: (s: string) => void; setSeed: (s: string) => void;
  firstName?: string; lastName?: string;
  dirtyBar: React.ReactNode;
}) {
  const theme = useTheme();
  const config: AvatarConfig = { style, seed };
  const inits = initialsFn(firstName, lastName);

  return (
    <Stack spacing={2.5}>
      <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
        <Box sx={{
          width: 46, height: 46, borderRadius: 3, display: "grid", placeItems: "center",
          background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
          border: "1px solid rgba(56,189,248,.2)", "& svg": { fontSize: 22 },
        }}>
          <PersonOutlined />
        </Box>
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 950, letterSpacing: -0.2 }}>Avatar</Typography>
          <Typography variant="body2" color="text.secondary">
            Pick a style and randomize until you like it. Preview is instant — save to persist.
          </Typography>
        </Box>
      </Stack>

      <Divider sx={{ opacity: 0.25 }} />

      {dirtyBar}

      {/* Live preview + randomize */}
      <InnerCard sx={{ px: 2, py: 2, display: "flex", alignItems: "center", gap: 2 }}>
        <UserAvatar avatar={config} initials={inits} sx={{ width: 72, height: 72, fontSize: 26, fontWeight: 950 }} />
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography sx={{ fontWeight: 900, fontSize: 14 }}>{AVATAR_STYLES.find((s) => s.key === style)?.label ?? "Initials"}</Typography>
          <Typography variant="caption" color="text.secondary">seed: {seed || "—"}</Typography>
        </Box>
        <Button
          size="small" variant="outlined" startIcon={<CasinoOutlined />}
          onClick={() => setSeed(Math.random().toString(36).slice(2, 12))}
          sx={{ textTransform: "none", fontWeight: 800, borderRadius: 2 }}
        >
          Randomize
        </Button>
      </InnerCard>

      {/* Style grid */}
      <Stack spacing={1}>
        <CaptionLabel>Style</CaptionLabel>
        <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(84px, 1fr))", gap: 1 }}>
          {AVATAR_STYLES.map((s) => {
            const selected = s.key === style;
            const preview = renderAvatarDataUri({ style: s.key, seed: seed || "preview" });
            return (
              <Box
                key={s.key}
                role="button"
                tabIndex={0}
                onClick={() => setStyle(s.key)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setStyle(s.key); }}
                sx={{
                  cursor: "pointer", borderRadius: 2.5, p: 1,
                  display: "flex", flexDirection: "column", alignItems: "center", gap: 0.5,
                  border: `1px solid ${selected ? theme.palette.primary.main : alpha(theme.palette.divider, 0.5)}`,
                  background: selected ? alpha(theme.palette.primary.main, 0.08) : "transparent",
                  transition: "all .15s ease",
                }}
              >
                <Box component="img" src={preview} alt={s.label} sx={{ width: 44, height: 44 }} />
                <Typography variant="caption" sx={{ fontWeight: selected ? 900 : 700, fontSize: 10.5 }}>{s.label}</Typography>
              </Box>
            );
          })}
        </Box>
      </Stack>
    </Stack>
  );
}
```

- [ ] **Step 3: Wire the panel into ProfilePage — state + section**

In `suspicious-ui/src/pages/ProfilePage.tsx`:

1. Add to the `Section` type (line ~72): `type Section = "preferences" | "appearance" | "colors" | "avatar";`
2. Import the panel and helper near the other feature imports:
   ```tsx
   import { AvatarPanel } from "@/features/profile/AvatarPanel";
   import { randomSeed } from "@/features/profile/avatar";
   ```
3. Add local state near the other `React.useState` calls (after `pickedTheme`):
   ```tsx
   const [avatarStyle, setAvatarStyle] = React.useState<string>("");
   const [avatarSeed,  setAvatarSeed]  = React.useState<string>("");
   ```
4. In the `if (profileData !== prevProfileData)` sync block, after `setAutoSeasonal(...)`:
   ```tsx
   setAvatarStyle(profileData.avatar?.style ?? "");
   setAvatarSeed(profileData.avatar?.seed ?? "");
   ```

- [ ] **Step 4: Wire the panel into ProfilePage — dirty, save, reset, nav, render**

Still in `ProfilePage.tsx`:

1. Dirty detection (near `themeDirty`):
   ```tsx
   const avatarDirty =
     avatarStyle !== (baseProfile?.avatar?.style ?? "") ||
     avatarSeed  !== (baseProfile?.avatar?.seed  ?? "");
   ```
2. Save/reset handlers (near `saveAppearance`):
   ```tsx
   function saveAvatar() {
     const avatar = avatarStyle && avatarSeed ? { style: avatarStyle, seed: avatarSeed } : {};
     queryClient.setQueryData<UserProfile>(["profile"], (prev) => ({
       ...(prev ?? baseProfile as UserProfile),
       avatar: avatar as UserProfile["avatar"],
     }));
     appearanceMutation.mutate({ avatar: avatar as any });
   }
   function resetAvatar() {
     setAvatarStyle(baseProfile?.avatar?.style ?? "");
     setAvatarSeed(baseProfile?.avatar?.seed ?? "");
   }
   ```
   If the user selects a style but the seed is empty, seed it on selection — change the panel's `setStyle` call site so ProfilePage passes a wrapper:
   ```tsx
   const setStyleWithSeed = (s: string) => {
     setAvatarStyle(s);
     if (!avatarSeed) setAvatarSeed(randomSeed());
   };
   ```
3. Add a nav entry to the `NAV` array (after the `colors` entry):
   ```tsx
   {
     key: "avatar" as Section,
     label: "Avatar",
     sub: "Your profile picture",
     icon: <PersonOutlined />,
     dirty: avatarDirty,
   },
   ```
   (`PersonOutlined` is already imported in ProfilePage.)
4. Include avatar dirtiness in `anyDirty`:
   ```tsx
   const anyDirty = prefsDirty || themeDirty || avatarDirty;
   ```
5. Render the panel — extend the section switch in the content panel (after the `colors`/`ColorsPanel` branch). Change the final ternary so `colors` renders `<ColorsPanel />` and add an `avatar` branch:
   ```tsx
   ) : section === "colors" ? (
     <ColorsPanel />
   ) : (
     <AvatarPanel
       style={avatarStyle} seed={avatarSeed}
       setStyle={setStyleWithSeed} setSeed={setAvatarSeed}
       firstName={me.first_name} lastName={me.last_name}
       dirtyBar={
         <DirtyBar
           dirty={avatarDirty} saving={appearanceMutation.isPending}
           onSave={saveAvatar} onReset={resetAvatar}
           label="Unsaved avatar changes"
         />
       }
     />
   )}
   ```
   Note: `DirtyBar` is defined in ProfilePage — pass it in as shown so AvatarPanel stays presentational.

- [ ] **Step 5: Swap the hero avatar to UserAvatar**

Replace the hero `<Avatar>...{initials(me.first_name, me.last_name)}</Avatar>` block (ProfilePage ~line 645-653) with:
```tsx
<UserAvatar
  avatar={profileData?.avatar}
  initials={initials(me.first_name, me.last_name)}
  sx={{
    width: 62, height: 62, fontWeight: 950, fontSize: 22,
    position: "relative", zIndex: 1,
    bgcolor: isDark ? alpha("#fff", 0.07) : alpha(theme.palette.primary.main, 0.08),
    color: "text.primary",
    border: `2px solid ${isDark ? alpha("#0f172a", 0.9) : alpha("#fff", 0.9)}`,
  }}
/>
```
Add the import: `import { UserAvatar } from "@/features/profile/components/UserAvatar";`

- [ ] **Step 6: Run the full frontend suite + typecheck**

Run from `suspicious-ui/`:
```bash
pnpm test
pnpm build
```
Expected: all tests pass; build (tsc) succeeds with no type errors.

- [ ] **Step 7: Commit**

```bash
git add suspicious-ui/src/features/profile/api.ts suspicious-ui/src/features/profile/AvatarPanel.tsx suspicious-ui/src/pages/ProfilePage.tsx
git commit -m "feat(ui): avatar picker panel wired into profile page"
```

---

### Task 6: Show avatar in the sidebar chip

**Files:**
- Modify: `suspicious-ui/src/layouts/AppLayout.tsx`
- Modify: `suspicious-ui/src/layouts/components/navComponents.tsx` (`UserCard`, ~line 379-486)

**Interfaces:**
- Consumes: `getProfile`, `UserProfile` (existing `features/profile/api`); `UserAvatar` (Task 4); `AvatarConfig` (Task 3).
- Produces: `UserCard` gains an `avatar?: AvatarConfig | null` prop.

- [ ] **Step 1: Fetch the profile in AppLayout and pass avatar down**

In `suspicious-ui/src/layouts/AppLayout.tsx`:
1. Add imports:
   ```tsx
   import { getProfile } from "@/features/profile/api";
   ```
2. After the `meQuery`/`me` lines (~line 51-57), add:
   ```tsx
   const profileQuery = useQuery({
     queryKey: ["profile"],
     queryFn: getProfile,
     enabled: !!me,
     retry: false,
   });
   ```
3. Pass to `UserCard` (~line 303):
   ```tsx
   <UserCard
     slim={isSlim}
     me={me}
     avatar={profileQuery.data?.avatar}
     isElevated={isElevated}
     groups={groups}
     onClick={() => navigate("/profile")}
   />
   ```

- [ ] **Step 2: Accept + render the avatar in UserCard**

In `suspicious-ui/src/layouts/components/navComponents.tsx`:
1. Add imports near the top:
   ```tsx
   import { UserAvatar } from "@/features/profile/components/UserAvatar";
   import type { AvatarConfig } from "@/features/profile/avatar";
   ```
2. Add `avatar` to the `UserCard` props type and destructure:
   ```tsx
   export function UserCard({
     slim,
     me,
     avatar,
     isElevated,
     groups,
     onClick,
   }: {
     slim: boolean;
     me: Me | undefined;
     avatar?: AvatarConfig | null;
     isElevated: boolean;
     groups: string[];
     onClick?: () => void;
   }) {
   ```
3. **Slim variant** (~line 400-432): replace the inner `<Typography>{initial}</Typography>` with a small `UserAvatar` (keep the outer styled box):
   ```tsx
   <UserAvatar avatar={avatar} initials={initial} sx={{ width: 30, height: 30, fontSize: 14, fontWeight: 950, bgcolor: "transparent", color: isElevated ? primary : "text.primary" }} />
   ```
4. **Full variant** (~line 470-486): replace the `<Avatar ...>{initial}</Avatar>` with:
   ```tsx
   <UserAvatar
     avatar={avatar}
     initials={initial}
     sx={{
       width: 32, height: 32, fontSize: 13, fontWeight: 950,
       position: "relative", zIndex: 1,
       bgcolor: isElevated
         ? alpha(primary, isDark ? 0.2 : 0.12)
         : alpha(theme.palette.text.primary, isDark ? 0.07 : 0.05),
       color: isElevated ? primary : "text.primary",
       border: `1.5px solid ${isDark ? alpha("#0f172a", 0.9) : alpha("#fff", 0.9)}`,
     }}
   />
   ```

- [ ] **Step 3: Run the full frontend suite + build**

Run from `suspicious-ui/`:
```bash
pnpm test
pnpm build
```
Expected: all tests pass; build succeeds.

- [ ] **Step 4: Manual smoke (optional but recommended)**

Run `pnpm dev`, log in, open Profile → Avatar, pick a style, Randomize, Save. Confirm the hero and the sidebar chip both update. Reload to confirm persistence.

- [ ] **Step 5: Commit**

```bash
git add suspicious-ui/src/layouts/AppLayout.tsx suspicious-ui/src/layouts/components/navComponents.tsx
git commit -m "feat(ui): render custom avatar in sidebar user chip"
```

---

## Self-Review

**Spec coverage:**
- Storage (avatar JSONField, both models, migration) → Task 1. ✓
- API (reuse appearance, AvatarField, read serializers) → Task 2. ✓
- Render helper (deps, AVATAR_STYLES, renderAvatarDataUri, randomSeed) → Task 3. ✓
- Picker UI (nav section, panel, grid, randomize, DirtyBar, optimistic save) → Task 5. ✓
- Show everywhere (UserAvatar, hero, sidebar) → Tasks 4, 5 (hero), 6 (sidebar). ✓
- Testing (backend serializer tests, renderAvatarDataUri test, UserAvatar fallback test) → Tasks 2, 3, 4. ✓
- Out-of-scope items excluded. ✓

**Type consistency:** `AvatarConfig = {style, seed}` defined in Task 3, consumed identically in Tasks 4, 5, 6. `avatar` prop on `UserCard` (Task 6) matches `UserAvatar`'s `avatar?: AvatarConfig | null`. Backend `{style, seed}` shape matches frontend. `AVATAR_STYLES` keys match `ALLOWED_AVATAR_STYLES` (both: bottts, identicon, initials, avataaars, funEmoji, thumbs, shapes, notionists). ✓

**Placeholder scan:** No TBD/TODO; every code step has full code. ✓
