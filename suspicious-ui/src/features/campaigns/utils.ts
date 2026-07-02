import { type Layout } from "react-grid-layout/legacy";
import type { PcaPoint } from "@/features/campaigns/api";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const CLASS_COLORS: Record<string, string> = {
  SAFE: "#22C55E",
  UNWANTED: "#F59E0B",
  SUSPICIOUS: "#38BDF8",
  DANGEROUS: "#EF4444",
  UNKNOWN: "#94A3B8",
};

export const PCA_LABELS = ["SAFE", "UNWANTED", "SUSPICIOUS", "DANGEROUS"];

export const PANEL_KEYS = {
  CLASSIFICATION: "classification",
  PCA: "pca",
  VOLUME: "volume",
} as const;

export const BREAKPOINTS = { lg: 1200, md: 900, sm: 600, xs: 0 };
export const COLS = { lg: 12, md: 12, sm: 6, xs: 1 };
export const ROW_HEIGHT = 32;

// Layout: classification (left, tall) + PCA (right, tall) on top row,
// volume (full width) on bottom row.
export const DEFAULT_LAYOUTS: Partial<Record<string, Layout>> = {
  lg: [
    { i: PANEL_KEYS.CLASSIFICATION, x: 0, y: 0, w: 4, h: 14, minW: 3, minH: 8 },
    { i: PANEL_KEYS.PCA, x: 4, y: 0, w: 8, h: 14, minW: 4, minH: 8 },
    { i: PANEL_KEYS.VOLUME, x: 0, y: 14, w: 12, h: 12, minW: 6, minH: 8 },
  ],
  md: [
    { i: PANEL_KEYS.CLASSIFICATION, x: 0, y: 0, w: 5, h: 14, minW: 3, minH: 8 },
    { i: PANEL_KEYS.PCA, x: 5, y: 0, w: 7, h: 14, minW: 4, minH: 8 },
    { i: PANEL_KEYS.VOLUME, x: 0, y: 14, w: 12, h: 12, minW: 6, minH: 8 },
  ],
  sm: [
    { i: PANEL_KEYS.CLASSIFICATION, x: 0, y: 0, w: 6, h: 14, minH: 8 },
    { i: PANEL_KEYS.PCA, x: 0, y: 14, w: 6, h: 14, minH: 8 },
    { i: PANEL_KEYS.VOLUME, x: 0, y: 28, w: 6, h: 12, minH: 8 },
  ],
  xs: [
    { i: PANEL_KEYS.CLASSIFICATION, x: 0, y: 0, w: 1, h: 14, minH: 8 },
    { i: PANEL_KEYS.PCA, x: 0, y: 14, w: 1, h: 14, minH: 8 },
    { i: PANEL_KEYS.VOLUME, x: 0, y: 28, w: 1, h: 12, minH: 8 },
  ],
};

export const STORAGE_KEY = "campaigns:layouts";

// ---------------------------------------------------------------------------
// Layout persistence
// ---------------------------------------------------------------------------

export function loadLayouts(): Partial<Record<string, Layout>> {
  if (typeof window === "undefined") return DEFAULT_LAYOUTS;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_LAYOUTS;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed
      : DEFAULT_LAYOUTS;
  } catch {
    return DEFAULT_LAYOUTS;
  }
}

export function saveLayouts(layouts: Partial<Record<string, Layout>>) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(layouts));
  } catch {
    /* ignore */
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function compactLabel(text: string, max = 22) {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export function classColor(label: string) {
  return (
    CLASS_COLORS[(label || "UNKNOWN").toUpperCase()] ?? CLASS_COLORS.UNKNOWN
  );
}

export function normalizeLabel(label: string) {
  return (label || "UNKNOWN").toUpperCase();
}

export function dateOnly(iso: string) {
  return iso ? iso.slice(0, 10) : "";
}

export function toIndexMap(dates: string[]) {
  const map = new Map<string, number>();
  dates.forEach((d, i) => map.set(d, i));
  return map;
}

export function computeCampaignRects(points: PcaPoint[]) {
  const map = new Map<
    string,
    { name: string; minX: number; maxX: number; minY: number; maxY: number }
  >();

  for (const p of points) {
    const refs = Array.isArray(p.sourceRefs)
      ? p.sourceRefs.filter(Boolean)
      : [];
    if (!refs.length) continue;
    const key = refs.slice().sort().join(" | ");
    const name =
      refs.length <= 3 ? refs.join(", ") : `${refs.slice(0, 3).join(", ")}…`;
    const current = map.get(key);
    if (!current) {
      map.set(key, { name, minX: p.x, maxX: p.x, minY: p.y, maxY: p.y });
    } else {
      current.minX = Math.min(current.minX, p.x);
      current.maxX = Math.max(current.maxX, p.x);
      current.minY = Math.min(current.minY, p.y);
      current.maxY = Math.max(current.maxY, p.y);
    }
  }

  return Array.from(map.values()).map((b, idx) => {
    const padX = Math.max(0.2, (b.maxX - b.minX) * 0.1);
    const padY = Math.max(0.2, (b.maxY - b.minY) * 0.1);
    return {
      id: idx,
      name: b.name,
      x1: b.minX - padX,
      x2: b.maxX + padX,
      y1: b.minY - padY,
      y2: b.maxY + padY,
    };
  });
}
