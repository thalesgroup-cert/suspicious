import { describe, it, expect } from "vitest";
import {
  AVATAR_STYLES,
  renderAvatarDataUri,
  randomSeed,
  getStyleCategories,
  randomPaletteValue,
} from "@/features/profile/avatar";

describe("avatar helper", () => {
  it("exposes the agreed style allowlist", () => {
    const keys = AVATAR_STYLES.map((s) => s.key).sort();
    expect(keys).toEqual(
      ["avataaars", "bottts", "funEmoji", "identicon", "initials", "notionists", "shapes", "thumbs"],
    );
  });

  it("renders a deterministic svg data uri", () => {
    const a = renderAvatarDataUri({ style: "bottts", seed: "abc123" });
    const b = renderAvatarDataUri({ style: "bottts", seed: "abc123" });
    expect(a).toBe(b);
    expect(a.startsWith("data:image/svg+xml")).toBe(true);
  });

  it("produces different output for different seeds", () => {
    const a = renderAvatarDataUri({ style: "bottts", seed: "abc123" });
    const b = renderAvatarDataUri({ style: "bottts", seed: "zzz999" });
    expect(a).not.toBe(b);
  });

  it("falls back safely on unknown style", () => {
    const uri = renderAvatarDataUri({ style: "nope", seed: "x" });
    expect(uri).toBe("");
  });

  it("randomSeed returns a non-empty short string", () => {
    const s = randomSeed();
    expect(typeof s).toBe("string");
    expect(s.length).toBeGreaterThan(0);
    expect(s.length).toBeLessThanOrEqual(64);
  });

  it("renders deterministically with options and changes when an option changes", () => {
    const base = renderAvatarDataUri({ style: "avataaars", seed: "abc123" });
    const withOpt = renderAvatarDataUri({
      style: "avataaars",
      seed: "abc123",
      options: { eyes: ["happy"] },
    });
    const withOptAgain = renderAvatarDataUri({
      style: "avataaars",
      seed: "abc123",
      options: { eyes: ["happy"] },
    });
    expect(withOpt).toBe(withOptAgain);
    expect(withOpt).not.toBe(base); // pinning a category changes the render
  });

  it("keeps the no-options render identical to a plain {style, seed}", () => {
    const a = renderAvatarDataUri({ style: "bottts", seed: "abc123" });
    const b = renderAvatarDataUri({ style: "bottts", seed: "abc123", options: {} });
    expect(a).toBe(b);
  });

  it("extracts enum categories from a style schema", () => {
    const cats = getStyleCategories("avataaars");
    const keys = cats.map((c) => c.key);
    expect(cats.length).toBeGreaterThan(0);
    expect(keys).toContain("eyes");
    expect(keys).toContain("mouth");
    for (const c of cats) {
      expect(c.values.length).toBeGreaterThan(0);
      expect(typeof c.label).toBe("string");
      expect(c.label.length).toBeGreaterThan(0);
    }
  });

  it("returns an array (never throws) for a geometric style", () => {
    expect(Array.isArray(getStyleCategories("identicon"))).toBe(true);
  });

  it("returns [] for an unknown style", () => {
    expect(getStyleCategories("nope")).toEqual([]);
  });

  it("marks enum categories with kind 'enum'", () => {
    const cats = getStyleCategories("avataaars");
    const eyes = cats.find((c) => c.key === "eyes");
    expect(eyes?.kind).toBe("enum");
  });

  it("extracts color categories with their curated hex palette", () => {
    const cats = getStyleCategories("avataaars");
    const skin = cats.find((c) => c.key === "skinColor");
    expect(skin?.kind).toBe("color");
    expect(skin?.values.length).toBeGreaterThan(0);
    for (const hex of skin?.values ?? []) {
      expect(hex).toMatch(/^[a-fA-F0-9]{6}$/);
    }
  });

  it("includes backgroundColor as a color category on styles that support it", () => {
    const cats = getStyleCategories("avataaars");
    const bg = cats.find((c) => c.key === "backgroundColor");
    expect(bg?.kind).toBe("color");
    expect(bg?.values.length).toBeGreaterThan(0);
  });

  it("returns no color categories for a style with none (notionists)", () => {
    const cats = getStyleCategories("notionists");
    expect(cats.some((c) => c.kind === "color")).toBe(false);
    expect(cats.length).toBeGreaterThan(0); // still has enum categories
  });

  it("randomPaletteValue returns a value drawn from that category's palette", () => {
    const skin = getStyleCategories("avataaars").find((c) => c.key === "skinColor")!;
    const value = randomPaletteValue("avataaars", "skinColor");
    expect(value).toBeDefined();
    expect(skin.values).toContain(value);
  });

  it("randomPaletteValue returns undefined for an unknown style or category", () => {
    expect(randomPaletteValue("nope", "skinColor")).toBeUndefined();
    expect(randomPaletteValue("avataaars", "nope")).toBeUndefined();
  });
});
