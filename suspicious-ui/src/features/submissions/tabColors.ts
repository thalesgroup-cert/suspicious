import type { Theme } from "@mui/material/styles";
import { ensureContrast, flatten } from "@/shared/lib/contrast";

/**
 * Tab label colours that read at 4.5:1 on the sheet header: its paper and the hover-tinted top of its gradient
 * (see SheetHeader). Keeps the theme's secondary/primary hues; themes restyle MuiTab, so the drawer sets these itself.
 */
export function tabLabelColors(theme: Theme): { unselected: string; selected: string; backgrounds: string[] } {
  const { paper } = theme.palette.background;
  const backgrounds = [paper, flatten(theme.palette.action.hover, paper, 0.22)];
  const fit = (fg: string) => backgrounds.reduce((out, bg) => ensureContrast(out, bg), fg);
  return {
    unselected: fit(flatten(theme.palette.text.secondary, paper)),
    selected: fit(flatten(theme.palette.primary.main, paper)),
    backgrounds,
  };
}
