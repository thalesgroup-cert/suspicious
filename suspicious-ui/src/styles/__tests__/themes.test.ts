// src/styles/__tests__/themes.test.ts
import { describe, it, expect } from "vitest";
import { themes, edge, type ThemeName } from "@/styles/themes";
import { createTheme, alpha } from "@mui/material/styles";

const FIRST_FAMILY: Partial<Record<ThemeName, string>> = {
  light: "Inter Variable",
  midnight: "Inter Variable",
  paper: "Source Serif 4 Variable",
  // renee: only headings use the serif stack (body stays sans), so it is not asserted here
  sunrise: "Nunito Variable",
  high_contrast: "Inter Variable",
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

describe("edge", () => {
  it("derives the border colour from the theme's text colour", () => {
    const t = createTheme({ palette: { mode: "dark", text: { primary: "#112233" } } });
    expect(edge(t, 0.1)).toBe(`1px solid ${alpha("#112233", 0.1)}`);
  });

  it("a theme that sets its own MuiPaper border keeps it", () => {
    const root = themes.paper.components?.MuiPaper?.styleOverrides?.root;
    const resolved = typeof root === "function" ? root({ theme: themes.paper } as never) : root;
    expect(JSON.stringify(resolved)).not.toContain(alpha("#E5E7EB", 0.1));
  });
});

describe("heading sizes", () => {
  const px = (v: unknown) => {
    const s = String(v);
    return s.endsWith("rem") ? parseFloat(s) * 16 : parseFloat(s);
  };

  it("no theme falls back to MUI's default display sizes for h1-h5", () => {
    const tooBig = Object.entries(themes).flatMap(([name, theme]) =>
      (["h1", "h2", "h3", "h4", "h5"] as const)
        .filter((v) => px(theme.typography[v].fontSize) > 40)
        .map((v) => `${name} ${v}`),
    );
    expect(tooBig).toEqual([]);
  });

  it("a theme overriding h1-h5 without a size keeps the base sizes", () => {
    // paper sets fontFamily/weight/letterSpacing on h1-h5, never fontSize.
    const t = themes.paper.typography;
    expect([t.h1, t.h2, t.h3, t.h4, t.h5].map((v) => px(v.fontSize))).toEqual([28, 22, 18, 16, 14]);
  });

  it("every theme has a pageTitle variant: 20-28px, weight <= 800, not tightly tracked", () => {
    for (const [name, theme] of Object.entries(themes)) {
      const t = (theme.typography as unknown as Record<string, { fontSize?: unknown; fontWeight?: unknown; letterSpacing?: unknown }>).pageTitle;
      expect(t, name).toBeDefined();
      const size = px(t.fontSize);
      expect(size, name).toBeGreaterThanOrEqual(20);
      expect(size, name).toBeLessThanOrEqual(28);
      expect(Number(t.fontWeight), name).toBeLessThanOrEqual(800);
      const ls = String(t.letterSpacing ?? 0);
      const lsPx = ls.endsWith("em") ? parseFloat(ls) * size : parseFloat(ls);
      expect(lsPx, name).toBeGreaterThanOrEqual(-0.01 * size);
    }
  });
});
