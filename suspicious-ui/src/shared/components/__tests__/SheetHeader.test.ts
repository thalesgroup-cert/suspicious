import { describe, it, expect } from "vitest";
import { decomposeColor } from "@mui/material/styles";
import { themes, type ThemeName } from "@/styles/themes";
import { headerTint } from "../SheetHeader";

describe("SheetHeader tint", () => {
  for (const name of Object.keys(themes) as ThemeName[]) {
    it(`${name}: the gradient's top colour is barely-there (alpha <= 0.06)`, () => {
      expect(decomposeColor(headerTint(themes[name])).values[3] ?? 1).toBeLessThanOrEqual(0.06);
    });
  }
});
