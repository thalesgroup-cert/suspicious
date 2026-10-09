import type { Theme } from "@mui/material/styles";
import { ensureContrast, flatten } from "@/shared/lib/contrast";

/**
 * Tab label colours that read at 4.5:1 on the sheet header. The tabs sit at the bottom of the header, where its
 * gradient has faded to transparent, so the background is the paper itself. Keeps the theme's secondary/primary hues; themes restyle MuiTab, so the drawer sets these itself.
 */
export function tabLabelColors(theme: Theme): { unselected: string; selected: string; backgrounds: string[] } {
  const { paper } = theme.palette.background;
  const backgrounds = [paper];
  const fit = (fg: string) => backgrounds.reduce((out, bg) => ensureContrast(out, bg), fg);
  return {
    unselected: fit(flatten(theme.palette.text.secondary, paper)),
    selected: fit(flatten(theme.palette.primary.main, paper)),
    backgrounds,
  };
}
