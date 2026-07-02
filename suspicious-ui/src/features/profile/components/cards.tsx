import * as React from "react";
import { Box, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";

export { SoftCard } from "@/shared/components/SoftCard";

export function InnerCard(props: React.PropsWithChildren<{ sx?: object }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  return (
    <Box
      sx={{
        borderRadius: 2.5,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.14 : 0.55)}`,
        background: isDark
          ? alpha("#fff", 0.025)
          : alpha(theme.palette.background.paper, 0.6),
        ...props.sx,
      }}
    >
      {props.children}
    </Box>
  );
}

export function NavIcon({ icon, isDark }: { icon: React.ReactNode; isDark: boolean }) {
  const theme = useTheme();
  return (
    <Box
      sx={{
        width: 32, height: 32, borderRadius: 2,
        display: "grid", placeItems: "center",
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.6)}`,
        background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
        flexShrink: 0,
        "& svg": { fontSize: 17 },
      }}
    >
      {icon}
    </Box>
  );
}

export function CaptionLabel({ children }: { children: React.ReactNode }) {
  return (
    <Typography
      variant="caption" color="text.disabled"
      sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.6, fontSize: 10.5, display: "block" }}
    >
      {children}
    </Typography>
  );
}
