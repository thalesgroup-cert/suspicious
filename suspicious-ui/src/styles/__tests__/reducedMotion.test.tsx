import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { AppThemeProvider } from "@/styles/ThemeStore";

describe("reduced motion", () => {
  it("the theme provider ships one global prefers-reduced-motion rule", () => {
    render(<AppThemeProvider><span /></AppThemeProvider>);
    const css = [...document.querySelectorAll("style")].map((s) => s.textContent ?? "").join("\n")
      + [...document.styleSheets].flatMap((sh) => { try { return [...sh.cssRules].map((r) => r.cssText); } catch { return []; } }).join("\n");
    expect(css).toMatch(/prefers-reduced-motion:\s*reduce/);
    expect(css).toMatch(/transition-duration:\s*0\.01ms\s*!important/);
  });
});
