
import * as React from "react";
import { Chip } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { composite, ensureContrast } from "@/shared/lib/contrast";

type Props = {
  label: string;
  /** Hex color from the semantic store; drives bg/border/text automatically. */
  color?: string;
  /** MUI palette name: fallback when no hex color is available. */
  muiColor?: "success" | "warning" | "error" | "info" | "default";
  icon?: React.ReactNode;
  minWidth?: number;
  size?: "small" | "medium";
};

export function Badge({ label, color, muiColor = "default", icon, minWidth = 128, size = "small" }: Props) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  // ── Hex color path (semantic store) ──────────────────────────────────────
  if (color) {
    const tint   = isDark ? 0.14 : 0.1;
    const bg     = alpha(color, tint);
    const border = alpha(color, isDark ? 0.35 : 0.45);
    // Text and icon keep the colour's hue but are nudged until they read at 4.5:1 on the tinted fill over the page.
    const text   = ensureContrast(color, composite(color, tint, theme.palette.background.paper));

    return (
      <Chip
        size={size}
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
      size={size}
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