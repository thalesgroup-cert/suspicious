import { describe, it, expect } from "vitest";
import { activeSum, formatShare, shares, valueText, wouldZeroTotal } from "@/features/settings/weights";

const row = (id: number, weight: number, is_active = true) => ({ id, weight, is_active });

describe("weights", () => {
  it("shares sum to 1 over all listed analyzers, inactive ones included", () => {
    const s = shares([row(1, 0.2), row(2, 0.3), row(3, 0.5, false)]);
    expect(s.get(1)).toBeCloseTo(0.2);
    expect(s.get(3)).toBeCloseTo(0.5);
    expect([...s.values()].reduce((a, b) => a + b, 0)).toBeCloseTo(1);
  });

  it("gives every analyzer 0 when the sum is 0", () => {
    const s = shares([row(1, 0), row(2, 0)]);
    expect([...s.values()]).toEqual([0, 0]);
  });

  it("activeSum ignores inactive analyzers and float noise", () => {
    expect(activeSum([row(1, 0.1), row(2, 0.2), row(3, 0.9, false)])).toBe(0.3);
  });

  it("wouldZeroTotal looks at active analyzers only", () => {
    expect(wouldZeroTotal([row(1, 0), row(2, 0), row(3, 0.9, false)])).toBe(true);
    expect(wouldZeroTotal([row(1, 0), row(2, 0.1)])).toBe(false);
    expect(wouldZeroTotal([])).toBe(true);
  });

  it("formats shares as rounded percentages, a dash for a zero sum", () => {
    expect(formatShare(0.1234, 1)).toBe("12%");
    expect(formatShare(0, 0)).toBe("-");
    expect(formatShare(0, 1)).toBe("0%");
  });

  it("builds the slider value text", () => {
    expect(valueText(0.4, 0.12)).toBe("0.4, 12% of the total");
    expect(valueText(0, 0)).toBe("0.0, 0% of the total");
  });
});
