import { type Layout } from "react-grid-layout/legacy";

export type ResponsiveLayouts = Partial<Record<string, Layout>>;

export const PANEL_KEYS = {
  KPI_TRENDS: "kpi-trends",
  OUTCOMES: "outcomes",
  BY_TYPE: "by-type",
  TOP_REPORTERS: "top-reporters",
} as const;

export const BREAKPOINTS = { lg: 1200, md: 900, sm: 600, xs: 0 };
export const COLS = { lg: 12, md: 12, sm: 6, xs: 1 };
export const ROW_HEIGHT = 32;

// Heights in rows (32px + 16px margin) fit the content of each panel: KPI cards
// ~180px, outcomes and by-type ~330px, ten reporters ~420px in one column and
// ~250px in the two columns a full-width panel gets.
const KPI_H = 5;
const MID_H = 8;
const REPORTERS_H = 10;
const REPORTERS_WIDE_H = 7;

function stacked(cols: number): Layout {
  return [
    { i: PANEL_KEYS.KPI_TRENDS, x: 0, y: 0, w: cols, h: KPI_H, minH: 4 },
    { i: PANEL_KEYS.OUTCOMES, x: 0, y: KPI_H, w: cols, h: MID_H, minH: 6 },
    { i: PANEL_KEYS.BY_TYPE, x: 0, y: KPI_H + MID_H, w: cols, h: MID_H, minH: 4 },
    { i: PANEL_KEYS.TOP_REPORTERS, x: 0, y: KPI_H + 2 * MID_H, w: cols, h: REPORTERS_H, minH: 4 },
  ];
}

// Wide: KPI row, outcomes beside by-type, reporters full width below, so a
// user without the reporters panel gets no hole in the grid.
const WIDE: Layout = [
  { i: PANEL_KEYS.KPI_TRENDS, x: 0, y: 0, w: 12, h: KPI_H, minW: 6, minH: 4 },
  { i: PANEL_KEYS.OUTCOMES, x: 0, y: KPI_H, w: 6, h: MID_H, minW: 4, minH: 6 },
  { i: PANEL_KEYS.BY_TYPE, x: 6, y: KPI_H, w: 6, h: MID_H, minW: 4, minH: 4 },
  { i: PANEL_KEYS.TOP_REPORTERS, x: 0, y: KPI_H + MID_H, w: 12, h: REPORTERS_WIDE_H, minW: 4, minH: 4 },
];

export const DEFAULT_LAYOUTS: ResponsiveLayouts = { lg: WIDE, md: WIDE, sm: stacked(6), xs: stacked(1) };

export function layoutStorageKey(userId?: string | number) {
  return `dashboard:layouts:${userId ?? "anonymous"}`;
}

const finite = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

/**
 * Saved positions are kept only for panels that exist now; panels a saved
 * layout lacks (older versions) take their default, unknown keys are dropped.
 */
function withDefaults(saved: Record<string, unknown>): ResponsiveLayouts {
  return Object.fromEntries(
    Object.entries(DEFAULT_LAYOUTS).map(([bp, defaults]) => {
      const items = Array.isArray(saved[bp]) ? (saved[bp] as Array<Record<string, unknown>>) : [];
      return [
        bp,
        defaults!.map((d) => {
          const s = items.find((it) => it?.i === d.i);
          if (!s || ![s.x, s.y, s.w, s.h].every(finite)) return d;
          return { ...d, x: s.x as number, y: s.y as number, w: Math.max(s.w as number, d.minW ?? 1), h: Math.max(s.h as number, d.minH ?? 1) };
        }),
      ];
    })
  );
}

export function loadLayouts(key: string): ResponsiveLayouts {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(key) ?? "null");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? withDefaults(parsed as Record<string, unknown>)
      : DEFAULT_LAYOUTS;
  } catch {
    return DEFAULT_LAYOUTS;
  }
}

/** True when every position in `layouts` matches the default (panels missing from it count as default). */
export function isDefaultLayout(layouts: ResponsiveLayouts): boolean {
  return Object.entries(layouts).every(([bp, items]) =>
    (items ?? []).every((it) => {
      const d = DEFAULT_LAYOUTS[bp]?.find((x) => x.i === it.i);
      return !d || (d.x === it.x && d.y === it.y && d.w === it.w && d.h === it.h);
    })
  );
}

export function clearLayouts(key: string) {
  try {
    window.localStorage.removeItem(key);
  } catch {
    /* blocked storage: nothing was saved either */
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
