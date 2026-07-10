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

export type AvatarConfig = {
  style: string;
  seed: string;
  options?: Record<string, string[]>;
};

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
  const options = config.options ?? {};
  const cacheKey = `${config.style}|${config.seed}|${JSON.stringify(options)}`;
  const hit = cache.get(cacheKey);
  if (hit !== undefined) return hit;
  const uri = createAvatar(style as never, { seed: config.seed, ...options }).toDataUri();
  cache.set(cacheKey, uri);
  return uri;
}

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

export function randomSeed(): string {
  return Math.random().toString(36).slice(2, 12);
}
