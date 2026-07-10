
import * as React from "react";
import { Chip } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { contrastText } from "@/styles/colorStore";

type Props = {
  label: string;
  /** Hex color from the semantic store — drives bg/border/text automatically. */
  color?: string;
  /** MUI palette name — fallback when no hex color is available. */
  muiColor?: "success" | "warning" | "error" | "info" | "default";
  icon?: React.ReactNode;
  minWidth?: number;
};

export function Badge({ label, color, muiColor = "default", icon, minWidth = 128 }: Props) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  // ── Hex color path (semantic store) ──────────────────────────────────────
  if (color) {
    const bg     = alpha(color, isDark ? 0.14 : 0.1);
    const border = alpha(color, isDark ? 0.35 : 0.45);
    const text   = color;

    return (
      <Chip
        size="small"
        icon={icon as any}
        label={label}
        variant="outlined"
        sx={{
          fontWeight: 900,
          minWidth,
          justifyContent: "center",
          bgcolor:     bg,
          borderColor: border,
          color:       text,
          "& .MuiChip-icon": { color: "inherit" },
          "& .MuiChip-label": { width: "100%", textAlign: "center" },
        }}
      />
    );
  }

  // ── MUI color fallback ────────────────────────────────────────────────────
  return (
    <Chip
      size="small"
      icon={icon as any}
      label={label}
      color={muiColor === "default" ? undefined : muiColor}
      variant={muiColor === "default" ? "outlined" : "outlined"}
      sx={{
        fontWeight: 900,
        minWidth,
        justifyContent: "center",
        "& .MuiChip-label": { width: "100%", textAlign: "center" },
      }}
    />
  );
}