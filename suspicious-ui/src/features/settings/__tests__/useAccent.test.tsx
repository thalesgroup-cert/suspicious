import { afterEach, describe, expect, it } from "vitest";
import { renderHook } from "@testing-library/react";

import { themes } from "@/styles/themes";
import { composite, contrastRatio, flatten } from "@/shared/lib/contrast";
import { AppThemeProvider } from "@/styles/ThemeStore";
import { useAccent } from "../useAccent";

afterEach(() => localStorage.removeItem("suspicious.theme"));

describe("useAccent", () => {
  it.each(Object.keys(themes) as (keyof typeof themes)[])("gives text 4.5:1 and marks 3:1 on every surface of the %s theme", (name) => {
    localStorage.setItem("suspicious.theme", name);
    const { palette } = themes[name];
    const { result } = renderHook(() => useAccent(), { wrapper: AppThemeProvider });
    const paper = palette.background.paper;
    const primary = flatten(palette.primary.main, paper);
    const surfaces = {
      paper,
      hover: flatten(palette.action.hover, paper),
      row: composite(primary, palette.mode === "dark" ? 0.2 : 0.12, paper),
      shell: composite(primary, 0.07, palette.background.default),
    };
    for (const [where, bg] of Object.entries(surfaces)) {
      expect(contrastRatio(result.current.text, bg), `${name} text on ${where}`).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatio(result.current.mark, bg), `${name} mark on ${where}`).toBeGreaterThanOrEqual(3);
    }
  });
});
