import { describe, it, expect, beforeEach, vi } from "vitest";
import { DEFAULT_LAYOUTS, layoutStorageKey, loadLayouts, saveLayouts } from "../layout";

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

  it("round-trips saved layouts", () => {
    const layouts = { lg: [{ i: "kpi-trends", x: 0, y: 0, w: 6, h: 4 }] };
    saveLayouts(KEY, layouts);
    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual(layouts);
    expect(loadLayouts(KEY)).toEqual(layouts);
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
});
