// src/shared/components/Badge.tsx
import * as React from "react";
import { Chip } from "@mui/material";

type Props = {
  label: string;
  color?: "success" | "warning" | "error" | "info" | "default";
  variant?: "filled" | "outlined";
  icon?: React.ReactNode;
  /** enforce identical visual width across badges */
  minWidth?: number;
};

export function Badge({ label, color = "default", variant = "outlined", icon, minWidth = 128 }: Props) {
  return (
    <Chip
      size="small"
      icon={icon as any}
      label={label}
      color={color === "default" ? undefined : (color as any)}
      variant={color === "default" ? "outlined" : variant}
      sx={{
        fontWeight: 900,
        minWidth,
        justifyContent: "center",
        "& .MuiChip-label": { width: "100%", textAlign: "center" },
      }}
    />
  );
}
