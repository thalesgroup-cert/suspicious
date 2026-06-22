import * as React from "react";
import { Box, Card, Chip, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";

// SoftCard — exactly mirrors the rest of the app.
export function SoftCard(props: React.PropsWithChildren<{ sx?: object }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Card
      elevation={0}
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

// Tighter inner card — same as SettingsPage / ProfilePage.
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

export function IconBadge({
  icon,
  size = 40,
  color,
}: {
  icon: React.ReactNode;
  size?: number;
  color?: string;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Box
      sx={{
        width: size,
        height: size,
        borderRadius: size <= 36 ? 2 : 3,
        display: "grid",
        placeItems: "center",
        flexShrink: 0,
        border: `1px solid ${
          color
            ? alpha(color, isDark ? 0.32 : 0.35)
            : alpha(theme.palette.divider, isDark ? 0.22 : 0.6)
        }`,
        background: color
          ? alpha(color, isDark ? 0.1 : 0.08)
          : "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
        color: color ?? "text.primary",
        "& svg": { fontSize: size * 0.46 },
      }}
    >
      {icon}
    </Box>
  );
}

export function SectionHeader({
  title,
  subtitle,
}: {
  title: string;
  subtitle?: string;
}) {
  return (
    <Stack spacing={0.5} sx={{ mb: 2 }}>
      <Typography variant="h5" sx={{ fontWeight: 950, letterSpacing: -0.4 }} >
        {title}
      </Typography>
      {subtitle ? (
        <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 720 }}>
          {subtitle}
        </Typography>
      ) : null}
    </Stack>
  );
}

export function CaptionLabel({ children }: { children: React.ReactNode }) {
  return (
    <Typography
      variant="caption"
      color="text.disabled"
      sx={{
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: 0.6,
        fontSize: 10.5,
        display: "block",
      }}
    >
      {children}
    </Typography>
  );
}

export function InfoPill(props: { icon: React.ReactElement; label: string }) {
  return (
    <Chip
      icon={props.icon}
      label={props.label}
      size="small"
      variant="outlined"
      sx={{
        borderRadius: 2.5,
        height: 28,
        fontWeight: 700,
        "& .MuiChip-label": { px: 1.1 },
      }}
    />
  );
}
