import { Box, Chip, type ChipProps } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";

import { readableOnTint } from "@/shared/lib/contrast";
import { useClassColors, type SeriesKey } from "@/features/campaigns/utils";

const TINT = 0.18;

/**
 * A class name in the class colour, the same one the map and the mix use, so one label has one colour on the page.
 * Pass `onClick` for a toggle; `on={false}` draws it struck through.
 */
export default function ClassChip({ k, label, on = true, ...rest }: { k: SeriesKey; label: string; on?: boolean } & Omit<ChipProps, "label" | "color" | "variant" | "icon" | "sx">) {
  const theme = useTheme();
  const color = useClassColors()[k];
  const backgrounds = [theme.palette.background.paper, theme.palette.background.default];
  // The dot sits on the chip's own tint, where the plain class colour (3:1 on the card) can fall under 3:1.
  const dotColor = on ? readableOnTint(color, color, TINT, backgrounds, 3) : color;

  return (
    <Chip
      size="small"
      variant="outlined"
      label={label}
      // Off is a hollow ring, so the state is not carried by colour and strike-through alone.
      icon={<Box component="span" aria-hidden sx={{ boxSizing: "border-box", width: 8, height: 8, borderRadius: "50%", border: "2px solid", borderColor: dotColor, bgcolor: on ? dotColor : "transparent", ml: "6px !important" }} />}
      sx={{
        borderColor: on ? color : "divider",
        // Tinted, not filled: white on orange/cyan fell to about 2:1 (audit C7).
        bgcolor: on ? alpha(color, TINT) : "transparent",
        color: on ? readableOnTint(theme.palette.text.primary, color, TINT, backgrounds) : "text.secondary",
        textDecoration: on ? "none" : "line-through",
      }}
      {...rest}
    />
  );
}
