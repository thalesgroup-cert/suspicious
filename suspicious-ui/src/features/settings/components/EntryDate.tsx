import { Typography } from "@mui/material";
import type { SxProps, Theme } from "@mui/material/styles";

/** "<label> <date>" as a time element; nothing for a missing or unparseable timestamp so "Invalid Date" never shows. */
export function EntryDate({ iso, label, sx }: { iso?: string; label: string; sx?: SxProps<Theme> }) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return (
    <Typography
      component="time"
      variant="caption"
      color="text.secondary"
      dateTime={iso}
      title={d.toLocaleString()}
      sx={sx}
    >
      {label} {d.toLocaleDateString()}
    </Typography>
  );
}
