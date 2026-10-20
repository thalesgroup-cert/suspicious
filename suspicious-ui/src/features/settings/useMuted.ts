import { useTheme } from "@mui/material/styles";

import { ensureContrast, flatten } from "@/shared/lib/contrast";

/** text.secondary pushed to 4.5:1 on paper: in a few themes the raw colour is under that, and tiles print real information in it. */
export function useMuted(): string {
  const { text, background } = useTheme().palette;
  return ensureContrast(flatten(text.secondary, background.paper), background.paper, 4.5);
}
