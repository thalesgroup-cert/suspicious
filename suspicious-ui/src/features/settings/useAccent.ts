import { useMemo } from "react";
import { useTheme } from "@mui/material/styles";

import { composite, ensureContrast, flatten } from "@/shared/lib/contrast";

/**
 * The theme accent pushed far enough to read as text (4.5:1) and as a mark (3:1) on every surface the settings page puts it on:
 * paper, the translucent hover bar, a hovered selected row (primary tint) and the bare shell (AppLayout's primary glow).
 * The raw accent is a fill colour and is under 3:1 as text in several themes.
 */
export function useAccent(): { text: string; mark: string } {
  const theme = useTheme();
  const { background, action, primary, mode } = theme.palette;
  return useMemo(() => {
    const accent = flatten(primary.main, background.paper);
    const surfaces = [
      background.paper,
      flatten(action.hover, background.paper),
      composite(accent, mode === "dark" ? 0.2 : 0.12, background.paper),
      composite(accent, 0.07, background.default),
    ];
    const push = (min: number) => surfaces.reduce((out, bg) => ensureContrast(out, bg, min), accent);
    // A little over the thresholds: the card and shell are translucent, so the colour behind a label is an estimate to about 0.2:1.
    return { text: push(4.7), mark: push(3.2) };
  }, [background.paper, background.default, action.hover, primary.main, mode]);
}
