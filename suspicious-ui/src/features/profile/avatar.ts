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
  /** Presigned MinIO URL, present only when style === "upload". Server-populated; never sent by the client. */
  url?: string;
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

export type StyleCategory = {
  key: string;
  label: string;
  kind: "enum" | "color";
  values: string[];
};

const categoryCache = new Map<string, StyleCategory[]>();

function prettifyLabel(key: string): string {
  return key
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (c) => c.toUpperCase())
    .trim();
}

export function getStyleCategories(styleKey: string): StyleCategory[] {
  const hit = categoryCache.get(styleKey);
  if (hit) return hit;
  const style = STYLE_MAP.get(styleKey) as unknown as
    | { schema?: { properties?: Record<string, unknown> } }
    | undefined;
  const props = style?.schema?.properties ?? {};
  const cats: StyleCategory[] = [];
  for (const [key, raw] of Object.entries(props)) {
    const p = raw as {
      type?: string;
      items?: { enum?: unknown[]; pattern?: string };
      default?: unknown[];
    };
    if (p?.type !== "array") continue;
    if (p.items?.pattern) {
      const palette = Array.isArray(p.default)
        ? p.default.filter((v): v is string => typeof v === "string")
        : [];
      if (palette.length > 0) {
        cats.push({ key, label: prettifyLabel(key), kind: "color", values: palette });
      }
      continue;
    }
    const en = p.items?.enum;
    if (Array.isArray(en) && en.length > 0 && en.every((v) => typeof v === "string")) {
      cats.push({ key, label: prettifyLabel(key), kind: "enum", values: en as string[] });
    }
  }
  categoryCache.set(styleKey, cats);
  return cats;
}

export function randomPaletteValue(styleKey: string, categoryKey: string): string | undefined {
  const cat = getStyleCategories(styleKey).find((c) => c.key === categoryKey);
  if (!cat || cat.values.length === 0) return undefined;
  return cat.values[Math.floor(Math.random() * cat.values.length)];
}

export function randomSeed(): string {
  return Math.random().toString(36).slice(2, 12);
}
