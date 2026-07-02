import { describe, it, expect } from "vitest";
import { DANGER_COLORS, DANGER_ORDER, fmtDate, short, sum } from "@/features/home/utils";

describe("short", () => {
  it("trims and returns within the limit", () => {
    expect(short("  hi  ")).toBe("hi");
    expect(short("abc", 5)).toBe("abc");
  });

  it("truncates past the limit and tolerates undefined", () => {
    expect(short("abcdef", 4)).toBe("abc…");
    expect(short(undefined)).toBe("");
  });
});

describe("fmtDate", () => {
  it("returns an em-dash for missing or invalid dates", () => {
    expect(fmtDate(undefined)).toBe("—");
    expect(fmtDate("not-a-date")).toBe("—");
  });

  it("formats a valid ISO date", () => {
    // Locale-dependent formatting, but a real date must not be the em-dash.
    expect(fmtDate("2026-06-22T10:00:00Z")).not.toBe("—");
  });
});

describe("sum", () => {
  it("adds the values, empty sums to 0", () => {
    expect(sum([1, 2, 3])).toBe(6);
    expect(sum([])).toBe(0);
  });
});

describe("danger constants", () => {
  it("orders labels and maps every label to a color", () => {
    expect(DANGER_ORDER).toEqual(["Safe", "Inconclusive", "Suspicious", "Dangerous"]);
    for (const label of DANGER_ORDER) {
      expect(DANGER_COLORS[label]).toMatch(/^#[0-9A-Fa-f]{6}$/);
    }
  });
});
