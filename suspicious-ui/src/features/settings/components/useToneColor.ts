import { useTheme } from "@mui/material/styles";

import { composite, ensureContrast, flatten } from "@/shared/lib/contrast";
import { useResultColors } from "@/styles/colorStore";
import type { StatusTone } from "./StatusLabel";

/**
 * The colour of a status tone, pushed to `min` contrast (4.5 for text, 3 for icons and marks) on every surface the settings page puts it on:
 * paper, a hovered selected row (primary tint) and the bare shell (AppLayout's primary glow over the page colour).
 */
export function useToneColor(): (tone: StatusTone, min: number) => string {
  const theme = useTheme();
  const result = useResultColors();
  const paper = theme.palette.background.paper;
  const primary = flatten(theme.palette.primary.main, paper);
  const surfaces = [
    paper,
    composite(primary, theme.palette.mode === "dark" ? 0.2 : 0.12, paper),
    composite(primary, 0.07, theme.palette.background.default),
  ];
  const base: Record<StatusTone, string> = {
    ok: result.safe.main,
    warning: result.suspicious.main,
    danger: result.dangerous.main,
    // text.secondary and primary can be translucent or non-hex; flattening gives the opaque colour the user sees.
    neutral: flatten(theme.palette.text.secondary, paper),
    info: primary,
  };
  return (tone, min) => surfaces.reduce((out, bg) => ensureContrast(out, bg, min), base[tone]);
}
