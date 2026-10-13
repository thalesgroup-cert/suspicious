import { type Layout } from "react-grid-layout/legacy";

export type ResponsiveLayouts = Partial<Record<string, Layout>>;

export const PANEL_KEYS = {
  KPI_TRENDS: "kpi-trends",
  TOP_PREFIXES: "top-prefixes",
  THREAT_DISTRIBUTION: "threat-distribution",
} as const;

export const BREAKPOINTS = { lg: 1200, md: 900, sm: 600, xs: 0 };
export const COLS = { lg: 12, md: 12, sm: 6, xs: 1 };
export const ROW_HEIGHT = 32;

const BOTTOM_H = 14;
const BOTTOM_MIN_H = 10;

export const DEFAULT_LAYOUTS: ResponsiveLayouts = {
  lg: [
    { i: PANEL_KEYS.KPI_TRENDS, x: 0, y: 0, w: 12, h: 6, minW: 6, minH: 4 },
    { i: PANEL_KEYS.TOP_PREFIXES, x: 0, y: 6, w: 8, h: BOTTOM_H, minW: 4, minH: BOTTOM_MIN_H },
    { i: PANEL_KEYS.THREAT_DISTRIBUTION, x: 8, y: 6, w: 4, h: BOTTOM_H, minW: 4, minH: BOTTOM_MIN_H },
  ],
  md: [
    { i: PANEL_KEYS.KPI_TRENDS, x: 0, y: 0, w: 12, h: 6, minW: 6, minH: 4 },
    { i: PANEL_KEYS.TOP_PREFIXES, x: 0, y: 6, w: 7, h: BOTTOM_H, minW: 4, minH: BOTTOM_MIN_H },
    { i: PANEL_KEYS.THREAT_DISTRIBUTION, x: 7, y: 6, w: 5, h: BOTTOM_H, minW: 4, minH: BOTTOM_MIN_H },
  ],
  sm: [
    { i: PANEL_KEYS.KPI_TRENDS, x: 0, y: 0, w: 6, h: 6, minH: 4 },
    { i: PANEL_KEYS.TOP_PREFIXES, x: 0, y: 6, w: 6, h: BOTTOM_H, minH: BOTTOM_MIN_H },
    { i: PANEL_KEYS.THREAT_DISTRIBUTION, x: 0, y: 6 + BOTTOM_H, w: 6, h: BOTTOM_H, minH: BOTTOM_MIN_H },
  ],
  xs: [
    { i: PANEL_KEYS.KPI_TRENDS, x: 0, y: 0, w: 1, h: 6, minH: 4 },
    { i: PANEL_KEYS.TOP_PREFIXES, x: 0, y: 6, w: 1, h: BOTTOM_H, minH: BOTTOM_MIN_H },
    { i: PANEL_KEYS.THREAT_DISTRIBUTION, x: 0, y: 6 + BOTTOM_H, w: 1, h: BOTTOM_H, minH: BOTTOM_MIN_H },
  ],
};

export function layoutStorageKey(userId?: string | number) {
  return `dashboard:layouts:${userId ?? "anonymous"}`;
}

export function loadLayouts(key: string): ResponsiveLayouts {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(key) ?? "null");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as ResponsiveLayouts)
      : DEFAULT_LAYOUTS;
  } catch {
    return DEFAULT_LAYOUTS;
  }
}

/** Only call from a user action (drag/resize stop, reset): never from onLayoutChange. */
export function saveLayouts(key: string, layouts: ResponsiveLayouts) {
  try {
    window.localStorage.setItem(key, JSON.stringify(layouts));
  } catch {
    /* storage full or blocked: the layout simply is not remembered */
  }
}
