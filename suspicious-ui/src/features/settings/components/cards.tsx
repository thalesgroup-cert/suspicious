import * as React from "react";
import { Box, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { SearchOutlined } from "@mui/icons-material";

export { SoftCard } from "@/shared/components/SoftCard";

export function InnerCard(props: React.PropsWithChildren<{ sx?: object; hover?: boolean }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Box
      sx={{
        borderRadius: 2.5,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.14 : 0.55)}`,
        background: isDark ? alpha("#fff", 0.025) : alpha(theme.palette.background.paper, 0.6),
        transition: "border-color .15s ease, background .15s ease",
        ...(props.hover && {
          "&:hover": {
            borderColor: alpha(theme.palette.divider, isDark ? 0.28 : 0.8),
            background: isDark ? alpha("#fff", 0.04) : alpha(theme.palette.background.paper, 0.9),
          },
        }),
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
        width: 32,
        height: 32,
        borderRadius: 2,
        display: "grid",
        placeItems: "center",
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

export function EmptyList({ message }: { message: string }) {
  return (
    <Stack spacing={1} sx={{ py: 5, alignItems: "center", justifyContent: "center" }}>
      <Box
        sx={{
          width: 48,
          height: 48,
          borderRadius: 3,
          display: "grid",
          placeItems: "center",
          // Passing the string token, not alpha(): action.hover is a CSS variable here and alpha() turned it into 50% black.
          bgcolor: "action.hover",
          color: "text.secondary",
          "& svg": { fontSize: 26 },
        }}
      >
        <SearchOutlined />
      </Box>
      {/* text.secondary: the message tells the user how to add entries, so it must meet text contrast. */}
      <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 600, textAlign: "center" }}>
        {message}
      </Typography>
    </Stack>
  );
}
