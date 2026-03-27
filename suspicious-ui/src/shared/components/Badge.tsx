// src/shared/components/Badge.tsx
//
// Low-level chip component.
//
// Accepts either:
//   color  — a raw hex string from the semantic color store (preferred)
//   muiColor — a MUI palette name for cases where a semantic hex isn't
//              available (e.g. "default" fallback chips)
//
// When `color` (hex) is provided it takes full precedence and drives
// background, border, and text contrast automatically.
// When only `muiColor` is provided the MUI Chip color prop is used
// as before — so existing callers that pass muiColor still work.

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
    const text   = color; // use the main color as text in tinted mode

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
          // Icon inherits color from the chip via currentColor
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