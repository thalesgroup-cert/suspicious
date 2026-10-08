// src/styles/__tests__/themes.test.ts
import { describe, it, expect } from "vitest";
import { themes, type ThemeName } from "@/styles/themes";

const FIRST_FAMILY: Partial<Record<ThemeName, string>> = {
  light: "Inter Variable",
  midnight: "Inter Variable",
  paper: "Source Serif 4 Variable",
  // renee: only headings use the serif stack (body stays sans), so it is not asserted here
  sunrise: "Nunito Variable",
  high_contrast: "IBM Plex Mono",
  cyber: "IBM Plex Mono",
};

describe("theme fonts", () => {
  it("every theme resolves a non-empty font stack ending in a generic family", () => {
    for (const [name, theme] of Object.entries(themes)) {
      const stack = theme.typography.fontFamily ?? "";
      expect(stack, name).not.toBe("");
      expect(stack, name).toMatch(/(sans-serif|serif|monospace)$/);
    }
  });

  it("themes start their stack with the family that is actually bundled", () => {
    for (const [name, family] of Object.entries(FIRST_FAMILY)) {
      const stack = themes[name as ThemeName].typography.fontFamily ?? "";
      expect(stack.replace(/"/g, "").startsWith(family!), name).toBe(true);
    }
  });
});
