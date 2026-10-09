import { describe, it, expect } from "vitest";
import { contrastRatio, composite, ensureContrast } from "../contrast";

describe("ensureContrast", () => {
  it("keeps a passing colour", () => expect(ensureContrast("#000000", "#ffffff")).toBe("#000000"));
  it("darkens a failing colour on light, keeping the hue", () => {
    const out = ensureContrast("#22C55E", "#ffffff");
    expect(contrastRatio(out, "#ffffff")).toBeGreaterThanOrEqual(4.5);
    const [r, g, b] = [1, 3, 5].map((i) => parseInt(out.slice(i, i + 2), 16));
    expect(g).toBeGreaterThan(r); expect(g).toBeGreaterThan(b); // still green
  });
  it("lightens on dark", () => {
    const out = ensureContrast("#1E40AF", "#0b1220");
    expect(contrastRatio(out, "#0b1220")).toBeGreaterThanOrEqual(4.5);
  });
  it("never lowers contrast, even when the extreme cannot reach the floor", () => {
    for (const fg of ["#22C55E", "#777777", "#F59E0B"]) for (const bg of ["#ffffff", "#808080", "#000000"])
      expect(contrastRatio(ensureContrast(fg, bg, 21), bg)).toBeGreaterThanOrEqual(contrastRatio(fg, bg));
  });
  it("composite blends the fill over the background", () => expect(composite("#000000", 0.5, "#ffffff")).toBe("#808080"));
});
