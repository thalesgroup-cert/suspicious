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
