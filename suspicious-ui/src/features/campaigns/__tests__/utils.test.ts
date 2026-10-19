import { describe, it, expect } from "vitest";
import { classKey, classLabel, formatDay, normalizeLabel, sortRows } from "@/features/campaigns/utils";

describe("campaign helpers", () => {
  it("normalizeLabel upper-cases and defaults to UNKNOWN", () => {
    expect(normalizeLabel("safe")).toBe("SAFE");
    expect(normalizeLabel("")).toBe("UNKNOWN");
  });

  it("classKey keeps the four classes and puts everything else in UNKNOWN, named Unclassified", () => {
    expect(classKey("dangerous")).toBe("DANGEROUS");
    expect(classKey("UNKNOWN")).toBe("UNKNOWN");
    expect(classKey("")).toBe("UNKNOWN");
    expect(classKey("odd")).toBe("UNKNOWN");
    expect(classLabel("unwanted")).toBe("Unwanted");
    expect(classLabel("UNKNOWN")).toBe("Unclassified");
  });

  it("formatDay shows the UTC day of a date or datetime", () => {
    expect(formatDay("2026-10-12")).toBe("12 Oct");
    expect(formatDay("2026-10-12T23:30:00Z")).toBe("12 Oct");
    expect(formatDay("")).toBe("—");
  });

  it("sortRows sorts strings and numbers both ways, nulls last, without mutating", () => {
    const rows = [{ v: 2 as number | null }, { v: null }, { v: 10 }];
    expect(sortRows(rows, (r) => r.v, "asc").map((r) => r.v)).toEqual([2, 10, null]);
    expect(sortRows(rows, (r) => r.v, "desc").map((r) => r.v)).toEqual([10, 2, null]);
    expect(rows.map((r) => r.v)).toEqual([2, null, 10]);
    const words = [{ s: "b" }, { s: "A" }, { s: "c" }];
    expect(sortRows(words, (r) => r.s, "asc").map((r) => r.s)).toEqual(["A", "b", "c"]);
  });
});
