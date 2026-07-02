import * as React from "react";
import { Box, Card, CardContent, Divider, Stack, Typography } from "@mui/material";
import { alpha } from "@mui/material/styles";
import { useTheme } from "@mui/material/styles";
import { useThemeMode } from "@/styles/ThemeStore";

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
  const { capabilities } = useThemeMode();
  const { effects } = capabilities;

  // Metal theme: periodic ! badge on hover
  const isMetal = effects.hasAlertStates;
  const [hovered, setHovered] = React.useState(false);
  const [showExcl, setShowExcl] = React.useState(false);
  const timerRef = React.useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  React.useEffect(() => {
    if (!isMetal || !hovered) {
      clearTimeout(timerRef.current);
      return;
    }
    function schedule() {
      const delay = 600 + Math.random() * 1800;
      timerRef.current = setTimeout(() => {
        setShowExcl(true);
        timerRef.current = setTimeout(() => {
          setShowExcl(false);
          schedule();
        }, 1100);
      }, delay);
    }
    schedule();
    // Reset on cleanup (hover end / unmount) rather than synchronously in the body.
    return () => {
      clearTimeout(timerRef.current);
      setShowExcl(false);
    };
  }, [isMetal, hovered]);

  return (
    <Card
      onMouseEnter={isMetal ? () => setHovered(true) : undefined}
      onMouseLeave={isMetal ? () => setHovered(false) : undefined}
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
          sx={{ mb: 1, flexShrink: 0, alignItems: "center", justifyContent: "space-between" }}
        >
          <Stack direction="row" spacing={0.9} sx={{ alignItems: "center" }} >
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

            <Typography sx={{ fontWeight: 900, fontSize: 15 }} >
              {title}
            </Typography>
            {showExcl && (
              <Box
                component="span"
                aria-hidden
                sx={{
                  display: "inline-flex", alignItems: "center", justifyContent: "center",
                  width: 18, height: 18, borderRadius: "3px",
                  fontSize: 11, fontWeight: 900, fontFamily: '"IBM Plex Mono", monospace',
                  backgroundColor: "var(--mgs-alert, #E1061B)", color: "#fff",
                  ml: 0.75, flexShrink: 0,
                  animation: "exclamation 300ms cubic-bezier(.34,1.56,.64,1) both",
                }}
              >!</Box>
            )}
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