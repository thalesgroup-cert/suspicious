# DiceBear avatar customization — design

**Date:** 2026-07-01
**Status:** Approved
**Area:** `suspicious-ui` (ProfilePage, layout) + `Suspicious` profiles/api

## Goal

Let a user customize their profile avatar using [DiceBear](https://github.com/dicebear/dicebear).
Today both places that show a user avatar (the ProfilePage hero and the sidebar
user chip) render initials only. Add a picker so a user chooses a DiceBear style
and rerolls a seed; the chosen avatar shows everywhere.

## Decisions

- **Delivery:** bundle the DiceBear library (`@dicebear/core` + `@dicebear/collection`).
  SVGs render client-side, fully offline. No calls to `api.dicebear.com` — the
  hosted API would leak seeds to a third party and needs internet + CSP, wrong for
  a CERT/security tool.
- **Scope:** style + randomizable seed only. Stored config is `{ style, seed }`.
  No per-style option knobs, no background/flip, no image upload.
- **Placement:** everywhere — ProfilePage hero + `navComponents` sidebar chip.
  Fall back to initials when no avatar is set.

## Storage (backend)

Add one field to both `UserProfile` and `CISOProfile` (`profiles/models.py`):

```python
avatar = models.JSONField(default=dict, blank=True)
```

Same JSONField pattern as `semantic_colors`. Stored shape:

```json
{ "style": "bottts", "seed": "3f9ac1" }
```

`{}` (default) = no custom avatar → clients fall back to initials. One migration
(`0009_*`).

## API

Avatar is appearance data → reuse `PATCH /api/profile/appearance/`. No new endpoint.

Changes in `api/serializers/profile.py`:

- Add `"avatar"` to `UserProfileSerializer.Meta.fields` and
  `CISOProfileSerializer.Meta.fields` (read side / GET `/profile/`).
- Add `avatar = AvatarField(required=False)` to `AppearanceSerializer`.
- New `AvatarField(serializers.JSONField)`:
  - Empty object `{}` → allowed, clears avatar.
  - Non-empty → require `style` in `ALLOWED_AVATAR_STYLES` allowlist and
    `seed` a string of length 1..64. Reject anything else (unknown style,
    missing/oversized seed, extra keys dropped).

`ALLOWED_AVATAR_STYLES` lives in the serializer module and mirrors the frontend
`AVATAR_STYLES` list (kept in sync by hand — small, rarely changes).

The existing `AppearanceView.patch` already returns the full profile, so the
frontend cache updates with no extra work.

## Rendering helper (frontend)

New deps: `@dicebear/core`, `@dicebear/collection`.

New module `suspicious-ui/src/features/profile/avatar.ts`:

- `AVATAR_STYLES`: curated allowlist, ~8 styles —
  `bottts`, `identicon`, `initials`, `avataaars`, `funEmoji`, `thumbs`,
  `shapes`, `notionists`. Each entry maps a string key → the imported
  collection style object + a display label.
- `type AvatarConfig = { style: string; seed: string }`.
- `renderAvatarDataUri(config: AvatarConfig): string` — `createAvatar(style,
  { seed }).toDataUri()`. Memoized (keyed by `style|seed`) so grid re-renders
  are cheap and deterministic.
- `randomSeed(): string` — short random hex.

## Picker UI

Add a 4th section to `ProfilePage` nav, matching the existing
Preferences / Appearance / Colors pattern (each is a `Section` + panel + `DirtyBar`).

New `AvatarPanel` (co-located in ProfilePage or `features/profile/AvatarPanel.tsx`):

- Large live preview of the current `{style, seed}`.
- Style grid — each bundled style previewed with the current seed; clicking
  selects it.
- "Randomize" button — rerolls the seed (updates all previews).
- Standard `DirtyBar` save/reset. Save calls `updateAppearance({ avatar })`,
  optimistic `queryClient.setQueryData(["profile"], ...)` like the other panels.

Types: extend `UserProfile` and `AppearancePayload` in
`features/profile/api.ts` with `avatar?: AvatarConfig`.

## Show everywhere

New shared `UserAvatar` component (`features/profile/components/UserAvatar.tsx`):

- Props: `avatar?: AvatarConfig | null`, `initials: string`, plus MUI `Avatar`
  `sx`/size passthrough.
- If `avatar?.style && avatar?.seed` → `<Avatar src={renderAvatarDataUri(avatar)} />`.
- Else → `<Avatar>{initials}</Avatar>`.

Wire into:

- `ProfilePage` hero avatar (currently inline `<Avatar>{initials(...)}</Avatar>`).
- `navComponents` sidebar user chip (currently `<Avatar>{initial}</Avatar>`) —
  needs the profile avatar config; the chip already has access to user/profile
  context, pass `avatar` through.

## Testing

Backend (`api/tests` or `profiles/tests.py`):
- Valid `{style, seed}` via PATCH appearance saves and round-trips on GET.
- Bad style rejected (400).
- Oversized seed (>64) / non-string seed rejected (400).
- Empty `{}` clears avatar.

Frontend:
- `renderAvatarDataUri` — same input → identical output (deterministic);
  returns a `data:image/svg+xml` URI; unknown style handled.
- `UserAvatar` — renders `img` src when config set; renders initials when not.

## Out of scope (add later if asked)

Per-style option knobs (hair/eyes/etc.), background color + flip toggles,
uploaded/custom-image avatars.
