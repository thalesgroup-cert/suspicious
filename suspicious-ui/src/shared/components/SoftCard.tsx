import * as React from "react";
import { Card } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";

// Theme-aware container card shared across feature surfaces.
export function SoftCard(props: React.PropsWithChildren<{ sx?: object }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Card
      sx={{
        borderRadius: 4,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.9)}`,
        background: isDark
          ? `linear-gradient(180deg, ${alpha("#fff", 0.03)}, ${alpha("#fff", 0.02)})`
          : `linear-gradient(180deg, ${alpha("#fff", 0.88)}, ${alpha(theme.palette.grey[50], 0.96)})`,
        boxShadow: isDark
          ? "0 12px 32px rgba(0,0,0,.28)"
          : "0 10px 28px rgba(15,23,42,.06)",
        ...props.sx,
      }}
    >
      {props.children}
    </Card>
  );
}
