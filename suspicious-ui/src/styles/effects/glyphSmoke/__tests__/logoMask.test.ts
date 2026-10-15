import { describe, it, expect } from "vitest";
import { buildLogoMask } from "../logoMask";

/** w×h RGBA, opaque inside the rectangle [x0,x1)×[y0,y1). */
function rect(w: number, h: number, x0: number, y0: number, x1: number, y1: number) {
  const data = new Uint8ClampedArray(w * h * 4);
  for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) data[(y * w + x) * 4 + 3] = 255;
  return data;
}

describe("buildLogoMask", () => {
  const w = 40, h = 40;
  const m = buildLogoMask(rect(w, h, 10, 10, 30, 30), w, h);
  const at = (a: Float32Array, x: number, y: number) => a[y * w + x];

  it("fills the silhouette and leaves the outside empty", () => {
    expect(at(m.fill, 20, 20)).toBeCloseTo(1);
    expect(at(m.fill, 1, 1)).toBe(0);
  });

  it("keeps the rim, not the interior, in the edge mask", () => {
    expect(at(m.edge, 20, 20)).toBe(0);
    expect(at(m.edge, 10, 20)).toBeGreaterThan(0.3);
  });

  it("keeps every value in [0, 1]", () => {
    for (const a of [m.fill, m.edge]) for (const v of a) { expect(v).toBeGreaterThanOrEqual(0); expect(v).toBeLessThanOrEqual(1); }
  });

  it("ignores near-transparent pixels", () => {
    const faint = new Uint8ClampedArray(w * h * 4);
    for (let i = 0; i < w * h; i++) faint[i * 4 + 3] = 20;
    expect(Math.max(...buildLogoMask(faint, w, h).fill)).toBe(0);
  });
});
