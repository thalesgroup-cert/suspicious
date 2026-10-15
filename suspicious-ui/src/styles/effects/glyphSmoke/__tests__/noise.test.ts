import { describe, it, expect } from "vitest";
import { fbm } from "../noise";

describe("fbm", () => {
  it("stays within [0, 1]", () => {
    for (let i = 0; i < 2000; i++) {
      const v = fbm(i * 0.37, i * 0.11 - 40, i * 0.05);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
    }
  });

  it("is deterministic and drifts with time", () => {
    expect(fbm(3.2, 4.1, 0.5)).toBe(fbm(3.2, 4.1, 0.5));
    expect(fbm(3.2, 4.1, 0.5)).not.toBe(fbm(3.2, 4.1, 2.5));
  });
});
