// src/features/dashboard/components/SoftCard.tsx
import * as React from "react";
import { Box, Card, CardContent, Divider, Stack, Typography } from "@mui/material";
import { alpha } from "@mui/material/styles";
import { useTheme } from "@mui/material/styles";

// ---------------------------------------------------------------------------
// SoftCard — theme-aware card shell shared across all dashboard panels.
// Replaces every local GlassCard copy (KpiTrendPanels, ThreatDistributionPanel,
// TopPrefixesPanel, KpiGrid). Single source of truth.
// ---------------------------------------------------------------------------

export type SoftCardProps = React.PropsWithChildren<{
  title: string;
  icon?: React.ReactNode;
  right?: React.ReactNode;
  /** Extra sx forwarded to the root Card */
  sx?: object;
  /** Extra sx forwarded to CardContent */
  contentSx?: object;
  /** When true, children get flex:1 + minHeight:0 wrapper (panels that fill height) */
  fillHeight?: boolean;
}>;

export function SoftCard({
  title,
  icon,
  right,
  sx,
  contentSx,
  fillHeight = false,
  children,
}: SoftCardProps) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Card
      sx={{
        height: "100%",
        borderRadius: 3,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.9)}`,
        background: isDark
          ? `linear-gradient(180deg, ${alpha("#fff", 0.03)}, ${alpha("#fff", 0.02)})`
          : `linear-gradient(180deg, ${alpha("#fff", 0.88)}, ${alpha(
              theme.palette.grey[50],
              0.96
            )})`,
        boxShadow: isDark
          ? "0 12px 32px rgba(0,0,0,.28)"
          : "0 10px 28px rgba(15,23,42,.06)",
        ...sx,
      }}
    >
      <CardContent
        sx={{
          height: "100%",
          p: { xs: 1.5, md: 2 },
          display: "flex",
          flexDirection: "column",
          minHeight: 0,
          ...contentSx,
        }}
      >
        {/* Card header */}
        <Stack
          direction="row"
          alignItems="center"
          justifyContent="space-between"
          sx={{ mb: 1, flexShrink: 0 }}
        >
          <Stack direction="row" spacing={0.9} alignItems="center">
            {icon ? (
              <Box
                sx={{
                  width: 34,
                  height: 34,
                  borderRadius: 2,
                  display: "grid",
                  placeItems: "center",
                  border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.7)}`,
                  background:
                    "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                  "& svg": { fontSize: 18 },
                }}
              >
                {icon}
              </Box>
            ) : null}

            <Typography fontWeight={900} fontSize={15}>
              {title}
            </Typography>
          </Stack>

          {right ?? null}
        </Stack>

        <Divider sx={{ opacity: 0.25, mb: 1.5, flexShrink: 0 }} />

        {/* Card body */}
        {fillHeight ? (
          <Box sx={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
            {children}
          </Box>
        ) : (
          children
        )}
      </CardContent>
    </Card>
  );
}