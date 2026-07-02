import { describe, it, expect, beforeEach } from "vitest";
import type { PcaPoint } from "@/features/campaigns/api";
import {
  classColor,
  compactLabel,
  computeCampaignRects,
  dateOnly,
  DEFAULT_LAYOUTS,
  loadLayouts,
  normalizeLabel,
  saveLayouts,
  STORAGE_KEY,
  toIndexMap,
} from "@/features/campaigns/utils";

const pt = (x: number, y: number, sourceRefs?: string[]) =>
  ({ x, y, sourceRefs }) as unknown as PcaPoint;

describe("simple label helpers", () => {
  it("compactLabel truncates past the limit", () => {
    expect(compactLabel("short", 22)).toBe("short");
    expect(compactLabel("abcdef", 4)).toBe("abc…");
  });

  it("classColor maps case-insensitively with UNKNOWN fallback", () => {
    expect(classColor("safe")).toBe("#22C55E");
    expect(classColor("DANGEROUS")).toBe("#EF4444");
    expect(classColor("nope")).toBe("#94A3B8");
  });

  it("normalizeLabel upper-cases and defaults to UNKNOWN", () => {
    expect(normalizeLabel("safe")).toBe("SAFE");
    expect(normalizeLabel("")).toBe("UNKNOWN");
  });

  it("dateOnly takes the ISO date prefix", () => {
    expect(dateOnly("2026-06-22T10:30:00Z")).toBe("2026-06-22");
    expect(dateOnly("")).toBe("");
  });

  it("toIndexMap maps each date to its index", () => {
    const m = toIndexMap(["a", "b", "c"]);
    expect(m.get("a")).toBe(0);
    expect(m.get("c")).toBe(2);
    expect(m.size).toBe(3);
  });
});

describe("loadLayouts / saveLayouts", () => {
  beforeEach(() => localStorage.removeItem(STORAGE_KEY));

  it("returns the defaults when nothing is stored", () => {
    expect(loadLayouts()).toEqual(DEFAULT_LAYOUTS);
  });

  it("round-trips a saved layout object", () => {
    const layouts = { lg: [{ i: "x", x: 0, y: 0, w: 1, h: 1 }] };
    saveLayouts(layouts as never);
    expect(loadLayouts()).toEqual(layouts);
  });

  it("falls back to defaults on a non-object payload", () => {
    localStorage.setItem(STORAGE_KEY, "[1,2,3]");
    expect(loadLayouts()).toEqual(DEFAULT_LAYOUTS);
  });
});

describe("computeCampaignRects", () => {
  it("skips points without source refs", () => {
    expect(computeCampaignRects([pt(1, 1), pt(2, 2, [])])).toEqual([]);
  });

  it("builds a padded bounding box per campaign (grouped by refs)", () => {
    const rects = computeCampaignRects([
      pt(0, 0, ["c1"]),
      pt(2, 2, ["c1"]),
    ]);
    expect(rects).toHaveLength(1);
    expect(rects[0].name).toBe("c1");
    // span 2 -> pad = max(0.2, 2*0.1) = 0.2
    expect(rects[0].x1).toBeCloseTo(-0.2);
    expect(rects[0].x2).toBeCloseTo(2.2);
    expect(rects[0].y1).toBeCloseTo(-0.2);
    expect(rects[0].y2).toBeCloseTo(2.2);
  });

  it("uses the minimum pad for a single point", () => {
    const [r] = computeCampaignRects([pt(5, 5, ["solo"])]);
    expect(r.x1).toBeCloseTo(4.8);
    expect(r.x2).toBeCloseTo(5.2);
  });

  it("groups refs order-independently and truncates long names", () => {
    const rects = computeCampaignRects([
      pt(0, 0, ["b", "a"]),
      pt(1, 1, ["a", "b"]),
      pt(3, 3, ["w", "x", "y", "z"]),
    ]);
    expect(rects).toHaveLength(2);
    expect(rects[0].name).toBe("b, a");
    expect(rects[1].name).toBe("w, x, y…");
  });
});
