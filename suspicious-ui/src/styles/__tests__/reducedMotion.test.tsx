import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { AppThemeProvider } from "@/styles/ThemeStore";
import { themes, type ThemeName } from "@/styles/themes";

describe("reduced motion", () => {
  for (const name of Object.keys(themes) as ThemeName[]) {
    it(`${name}: MUI's motion setting follows the system preference`, () => {
      expect(themes[name].motion.reducedMotion).toBe("system");
    });
  }

  it("the global rule covers transitions and scrolling, not keyframe animations (progress bars and spinners keep moving)", () => {
    render(<AppThemeProvider><span /></AppThemeProvider>);
    const css = [...document.querySelectorAll("style")].map((s) => s.textContent ?? "").join("\n")
      + [...document.styleSheets].flatMap((sh) => { try { return [...sh.cssRules].map((r) => r.cssText); } catch { return []; } }).join("\n");
    expect(css).toMatch(/prefers-reduced-motion:\s*reduce/);
    expect(css).toMatch(/transition-duration:\s*0\.01ms\s*!important/);
    expect(css).toMatch(/scroll-behavior:\s*auto\s*!important/);
    expect(css).not.toMatch(/animation-duration:\s*0\.01ms/);
  });
});
