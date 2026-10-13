import { describe, it, expect, beforeEach, vi } from "vitest";
import { DEFAULT_LAYOUTS, PANEL_KEYS, isDefaultLayout, layoutStorageKey, loadLayouts, saveLayouts } from "../layout";

const KEY = layoutStorageKey(7);

describe("dashboard layout storage", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("keys layouts per user", () => {
    expect(KEY).toBe("dashboard:layouts:7");
    expect(layoutStorageKey(undefined)).toBe("dashboard:layouts:anonymous");
  });

  it("returns the defaults when nothing is saved", () => {
    expect(loadLayouts(KEY)).toBe(DEFAULT_LAYOUTS);
  });

  it("round-trips saved positions for known panels", () => {
    const layouts = { lg: [{ i: "kpi-trends", x: 0, y: 0, w: 6, h: 5 }] };
    saveLayouts(KEY, layouts);
    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual(layouts);
    const loaded = loadLayouts(KEY);
    expect(loaded.lg!.find((l) => l.i === PANEL_KEYS.KPI_TRENDS)).toMatchObject({ x: 0, y: 0, w: 6, h: 5 });
  });

  it("fills panels an older saved layout lacks from the defaults and drops unknown ones", () => {
    // A layout saved before the outcomes / by-type panels existed.
    localStorage.setItem(
      KEY,
      JSON.stringify({
        lg: [
          { i: "kpi-trends", x: 0, y: 0, w: 12, h: 6 },
          { i: "top-prefixes", x: 0, y: 6, w: 8, h: 14 },
          { i: "threat-distribution", x: 8, y: 6, w: 4, h: 14 },
        ],
        md: "garbage",
      })
    );
    const loaded = loadLayouts(KEY);
    for (const bp of Object.keys(DEFAULT_LAYOUTS)) {
      expect(loaded[bp]!.map((l) => l.i).sort()).toEqual(Object.values(PANEL_KEYS).sort());
    }
    expect(loaded.lg!.find((l) => l.i === PANEL_KEYS.KPI_TRENDS)).toMatchObject({ w: 12, h: 6 });
    expect(loaded.lg!.find((l) => l.i === PANEL_KEYS.OUTCOMES)).toEqual(
      DEFAULT_LAYOUTS.lg!.find((l) => l.i === PANEL_KEYS.OUTCOMES)
    );
    expect(loaded.md).toEqual(DEFAULT_LAYOUTS.md);
  });

  it("ignores saved items with invalid geometry and never shrinks below the minimum", () => {
    localStorage.setItem(
      KEY,
      JSON.stringify({
        lg: [
          { i: "kpi-trends", x: "0", y: 0, w: 12, h: 6 },
          { i: "outcomes", x: 0, y: 5, w: 1, h: 1 },
        ],
      })
    );
    const loaded = loadLayouts(KEY);
    const def = (i: string) => DEFAULT_LAYOUTS.lg!.find((l) => l.i === i)!;
    expect(loaded.lg!.find((l) => l.i === PANEL_KEYS.KPI_TRENDS)).toEqual(def(PANEL_KEYS.KPI_TRENDS));
    const outcomes = loaded.lg!.find((l) => l.i === PANEL_KEYS.OUTCOMES)!;
    expect(outcomes.w).toBe(def(PANEL_KEYS.OUTCOMES).minW);
    expect(outcomes.h).toBe(def(PANEL_KEYS.OUTCOMES).minH);
  });

  it("falls back to the defaults on invalid JSON or a non-object", () => {
    localStorage.setItem(KEY, "{not json");
    expect(loadLayouts(KEY)).toBe(DEFAULT_LAYOUTS);
    localStorage.setItem(KEY, "[1,2]");
    expect(loadLayouts(KEY)).toBe(DEFAULT_LAYOUTS);
    localStorage.setItem(KEY, "null");
    expect(loadLayouts(KEY)).toBe(DEFAULT_LAYOUTS);
  });

  it("does not throw when storage is unavailable", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("QuotaExceededError");
    });
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("SecurityError");
    });
    expect(() => saveLayouts(KEY, DEFAULT_LAYOUTS)).not.toThrow();
    expect(loadLayouts(KEY)).toBe(DEFAULT_LAYOUTS);
  });

  it("tells a moved layout from the default, ignoring panels the layout lacks", () => {
    expect(isDefaultLayout(DEFAULT_LAYOUTS)).toBe(true);
    const lg = DEFAULT_LAYOUTS.lg!;
    expect(isDefaultLayout({ lg: lg.filter((it) => it.i !== PANEL_KEYS.TOP_REPORTERS) })).toBe(true);
    expect(isDefaultLayout({ ...DEFAULT_LAYOUTS, lg: lg.map((it) => (it.i === PANEL_KEYS.OUTCOMES ? { ...it, x: 6 } : it)) })).toBe(false);
  });
});
