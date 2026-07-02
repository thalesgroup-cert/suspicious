# Schema-driven avatar customization — design

**Date:** 2026-07-02
**Status:** Approved
**Area:** `suspicious-ui` (features/profile: avatar helper + AvatarPanel) + `Suspicious` api serializer

## Goal

Let a user customize their DiceBear avatar per category (hair, eyes, mouth,
colors, …) instead of only rerolling a random seed. Today the picker
(`AvatarPanel`) offers a style grid plus a single "Randomize" button that
rerolls the seed. Add per-category carousels so a user can pin specific
choices while leaving the rest random.

This is the "per-style option knobs" item deferred as out-of-scope in
`2026-07-01-dicebear-avatar-design.md`.

## Decisions

- **Schema-driven, automatic.** Categories and their values are read at
  runtime from each DiceBear style's own `schema.properties`. No per-style
  hand-curation, no hardcoded category lists — a library upgrade that adds a
  category surfaces automatically.
- **Seed stays; Randomize stays.** The seed remains the base randomness for
  any category the user has *not* pinned. Pinned categories live in
  `options`. Randomize rerolls the seed: untouched categories change, pinned
  ones stay.
- **Bounded/loose backend validation.** `options` is accepted as a size-capped
  dict with no cross-check against the DiceBear schema. DiceBear silently
  ignores unknown keys, and the avatar only ever renders in the owner's own
  browser, so the only real risk is storage abuse — which the caps prevent.
- **Backward compatible.** Existing stored `{style, seed}` configs remain
  valid; `options` is optional and omission reproduces today's behavior.

## Config shape

`AvatarConfig` gains an optional `options` map:

```ts
type AvatarConfig = {
  style: string;
  seed: string;
  options?: Record<string, string[]>;   // category key -> chosen value(s)
};
```

Stored example:

```json
{
  "style": "avataaars",
  "seed": "3f9ac1",
  "options": { "top": ["shortHair01"], "eyes": ["happy"] }
}
```

DiceBear option values are arrays. A single-element array pins one choice
(`top: ["shortHair01"]`). A category absent from `options` is left to
DiceBear's seed-driven random selection over the full set. `{}`/omitted
`options` = current behavior. `{}` for the whole avatar still clears it
(falls back to initials), unchanged from the existing contract.

## Rendering helper (`suspicious-ui/src/features/profile/avatar.ts`)

- `renderAvatarDataUri(config)` — call becomes
  `createAvatar(style, { seed: config.seed, ...(config.options ?? {}) }).toDataUri()`.
  The memo cache key extends to `style|seed|JSON.stringify(options)`.
- New `getStyleCategories(styleKey: string): { key: string; label: string; values: string[] }[]`
  - Reads `STYLE_MAP.get(styleKey)?.schema?.properties`.
  - Includes a property only when it is an enum array of strings
    (`type: "array"`, `items.enum` present and non-empty). This naturally
    captures `top`, `eyes`, `mouth`, `clothing`, enum `*Color` categories,
    etc.
  - Excludes numeric `*Probability` properties and anything without a string
    enum (kept out of scope; see below).
  - `label`: camelCase → Title Case (`facialHairColor` → "Facial Hair Color").
  - Memoized per `styleKey` (schema is static).
- `randomSeed()` — unchanged.

No change to `AVATAR_STYLES`.

## Picker UI (`AvatarPanel`)

Extend the existing panel; keep the live preview, the style grid, and the
Randomize button. Add a **Categories** section below the style grid:

- `getStyleCategories(style)` drives the list; it re-derives when the selected
  style changes.
- One row per category: a label and a compact carousel
  `‹ prev | value | next ›` cycling that category's `values`. The rendered
  value comes from `options[key]?.[0]` when pinned, otherwise a muted
  "Auto" placeholder (the seed decides).
- Selecting/advancing a carousel sets `options[key] = [value]`. A small
  "Auto"/clear control per row deletes the key from `options` (back to
  seed-driven). Rows are keyboard-navigable (arrow/enter), mirroring the
  existing style-grid a11y.
- The section is scrollable; styles with many categories (avataaars ≈ 15
  enum categories) get a bounded, scrollable list rather than an unbounded
  panel.
- Randomize rerolls the seed only; it does not touch pinned `options`.

State in `ProfilePage` extends the existing avatar state with
`avatarOptions` (a `Record<string, string[]>`), synced from
`profileData.avatar?.options`, included in dirty detection, save, and reset
exactly like `avatarStyle`/`avatarSeed`. Save sends
`{ style, seed, options }` (or `{}` to clear) through the existing
`updateAppearance({ avatar })` path with the same optimistic
`setQueryData(["profile"], …)`.

`UserAvatar` needs no change — it already forwards the whole `avatar` config
to `renderAvatarDataUri`, which now honors `options`.

## Backend (`Suspicious/Suspicious/api/serializers/profile.py`)

Extend `AvatarField` to accept an optional `options` key alongside the
existing `style`/`seed` validation. Bounded/loose rules:

- `options` absent or `{}` → allowed; store as given (omit when empty).
- Must be a dict, at most **20** keys.
- Each key: a string, length 1..**32**.
- Each value: a string, or a list of strings; each string length 1..**64**;
  at most **20** items per list.
- Total serialized `options` length ≤ **2048** bytes.
- No cross-check against DiceBear style schemas.

On success, stored avatar is `{style, seed, options}` (options included only
when non-empty). Reject with 400 on any bound violation. The model field is
already `JSONField`; no migration required.

`ALLOWED_AVATAR_STYLES` and the `{}`-clears-avatar behavior are unchanged.

## Out of scope

- Numeric `*Probability` knobs and free-form (non-enum) color pickers —
  carousels cover enum categories only. Add later if wanted.
- Background color / flip toggles, image upload (still out per the prior
  spec).
- Strict server-side validation against the DiceBear schema (explicitly
  rejected in favor of bounded/loose).

## Testing

Frontend (`features/profile/__tests__/avatar.test.ts` + AvatarPanel):
- `renderAvatarDataUri` with `options` is deterministic (same input → same
  URI) and changes when a pinned option changes.
- `renderAvatarDataUri` without `options` matches the pre-change output for a
  given `{style, seed}` (backward-compat guard).
- `getStyleCategories("avataaars")` returns a non-empty list including known
  keys (e.g. `top`, `eyes`, `mouth`); `getStyleCategories("identicon")`
  behaves (returns whatever enum categories exist, possibly few) without
  throwing.
- AvatarPanel: picking a category carousel value pins it into `options`;
  "Auto"/clear removes it.

Backend (`api/tests/test_profile_avatar.py`):
- Valid `{style, seed, options:{top:["shortHair01"]}}` saves and round-trips
  on GET.
- Oversized `options` (too many keys / oversized value / blob > 2KB) → 400.
- `options` omitted still works (existing tests stay green).
