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

const STYLE_MAP = new Map<string, (typeof AVATAR_STYLES)[number]["style"]>(
  AVATAR_STYLES.map((s) => [s.key, s.style]),
);

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
