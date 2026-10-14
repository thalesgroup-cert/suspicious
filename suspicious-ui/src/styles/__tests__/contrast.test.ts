import { describe, it, expect } from "vitest";
import { themes, type ThemeName } from "@/styles/themes";
import { decomposeColor } from "@mui/material/styles";

function lum(color: string) {
  const [r, g, b] = decomposeColor(color).values.slice(0, 3).map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
const ratio = (a: string, b: string) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};
const flat = (c: string) => c; // text.secondary is alpha-blended below

function blend(fg: string, bg: string) {
  const f = decomposeColor(fg).values;
  const b = decomposeColor(bg).values;
  const a = f[3] ?? 1;
  return `rgb(${[0, 1, 2].map((i) => Math.round(f[i] * a + b[i] * (1 - a))).join(",")})`;
}

describe("theme contrast", () => {
  for (const [name, theme] of Object.entries(themes)) {
    const floor = (name as ThemeName) === "high_contrast" ? 7 : 4.5;
    const { text, background } = theme.palette;
    it(`${name}: primary text >= ${floor}:1 on background and paper`, () => {
      expect(ratio(flat(text.primary), background.default), "bg").toBeGreaterThanOrEqual(floor);
      expect(ratio(flat(text.primary), background.paper), "paper").toBeGreaterThanOrEqual(floor);
    });
    it(`${name}: secondary text >= ${floor}:1 on paper`, () => {
      expect(ratio(blend(text.secondary, background.paper), background.paper)).toBeGreaterThanOrEqual(floor);
    });
  }
});
