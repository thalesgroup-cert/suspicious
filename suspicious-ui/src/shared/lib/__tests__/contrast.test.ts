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
  it("matches WCAG's well-known grey pair (#777 fails, #767676 passes on white)", () => {
    expect(contrastRatio("#777777", "#ffffff")).toBeCloseTo(4.48, 2);
    expect(contrastRatio("#767676", "#ffffff")).toBeCloseTo(4.54, 2);
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 5);
    expect(contrastRatio(ensureContrast("#777777", "#ffffff"), "#ffffff")).toBeGreaterThanOrEqual(4.5); // 1% lightness steps land on #747474
  });
  it("is memoised without changing results", () => {
    const first = ensureContrast("#22C55E", "#ffffff");
    expect(ensureContrast("#22C55E", "#ffffff")).toBe(first);
    for (let i = 0; i < 600; i++) ensureContrast("#22C55E", `#${(i + 4096).toString(16).padStart(6, "0")}`); // overflow clears the cache
    expect(ensureContrast("#22C55E", "#ffffff")).toBe(first);
  });
});
