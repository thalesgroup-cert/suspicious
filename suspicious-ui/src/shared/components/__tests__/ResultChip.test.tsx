import { afterEach, beforeEach, describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { ThemeProvider } from "@mui/material/styles";
import { themes, type ThemeName } from "@/styles/themes";
import { ResultChip } from "../ResultChip";
import { RiskChip } from "@/features/submissions/components/AnalyzerReportCard";
import { PRESET_DEFAULT, useColorStore } from "@/styles/colorStore";
import { composite, contrastRatio } from "@/shared/lib/contrast";

const textOf = (result: string, theme: ThemeName) => {
  const { container } = render(<ThemeProvider theme={themes[theme]}><ResultChip result={result} /></ThemeProvider>);
  return getComputedStyle(container.querySelector(".MuiChip-root")!).color;
};
const BACKGROUNDS = ["paper", "default"] as const;
const tint = (hex: string, theme: ThemeName, bg: (typeof BACKGROUNDS)[number]) =>
  composite(hex, themes[theme].palette.mode === "dark" ? 0.14 : 0.1, themes[theme].palette.background[bg]);
const hue = (c: string) => { // dominant channel order is enough to tell hues apart
  const v = (c.match(/\d+/g) ?? []).map(Number).slice(0, 3);
  return v.map((x, i) => [x, i]).sort((a, b) => b[0] - a[0]).map((p) => p[1]).join("");
};

describe("ResultChip text contrast", () => {
  // The store persists to localStorage, shared across test files in the browser.
  beforeEach(() => useColorStore.getState().reset());
  afterEach(() => useColorStore.getState().reset());
  const variants: [string, string][] = [
    ["SAFE", PRESET_DEFAULT.result.safe.main], ["INCONCLUSIVE", PRESET_DEFAULT.result.inconclusive.main],
    ["SUSPICIOUS", PRESET_DEFAULT.result.suspicious.main], ["DANGEROUS", PRESET_DEFAULT.result.dangerous.main],
    ["FAILURE", PRESET_DEFAULT.status.failure.main], ["UNKNOWN", PRESET_DEFAULT.status.unknown.main],
  ];
  for (const name of Object.keys(themes) as ThemeName[]) {
    it(`${name}: every result reads at 4.5:1 on its tinted fill`, () => {
      for (const [result, hex] of variants) for (const bg of BACKGROUNDS) {
        expect(contrastRatio(textOf(result, name), tint(hex, name, bg)), `${result} in ${name} on ${bg}`).toBeGreaterThanOrEqual(4.5);
      }
    });
    it(`${name}: risk chips (all tones) read at 4.5:1`, () => {
      for (const tone of ["error", "warning", "success"] as const) for (const bg of BACKGROUNDS) {
        const { container } = render(<ThemeProvider theme={themes[name]}><RiskChip label="Risk" tone={tone} /></ThemeProvider>);
        const fg = getComputedStyle(container.querySelector(".MuiChip-root")!).color;
        const fill = composite(themes[name].palette[tone].main, 0.1, themes[name].palette.background[bg]);
        expect(contrastRatio(fg, fill), `${tone} in ${name} on ${bg}`).toBeGreaterThanOrEqual(4.5);
      }
    });
  }

  it("light SAFE is darker than the raw palette green but still green", () => {
    const c = textOf("SAFE", "light");
    expect(c).not.toBe("rgb(34, 197, 94)");
    expect(contrastRatio(c, "#ffffff")).toBeGreaterThan(contrastRatio("#22C55E", "#ffffff"));
    expect(hue(c)).toBe(hue("rgb(34,197,94)"));
  });

  it("a user colour keeps its hue and is adjusted only when needed", () => {
    useColorStore.getState().setResultColor("safe", "#1E3A8A"); // dark blue, passes on light
    expect(textOf("SAFE", "light")).toBe("rgb(30, 58, 138)");
    useColorStore.getState().setResultColor("safe", "#38BDF8"); // light blue, fails on light
    const c = textOf("SAFE", "light");
    expect(c).not.toBe("rgb(56, 189, 248)");
    expect(hue(c)).toBe(hue("rgb(56,189,248)"));
  });
});
